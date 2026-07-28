//! Safe tree-walk evaluator over lowered IR.
//!
//! The tree-walk evaluator is the permanent Phase-1 correctness oracle. These
//! first slices evaluate scalar and list literals, boolean control flow,
//! assertions, boolean operators, string/URI literals and concatenation, list-spine
//! concatenation, static and recursive static attribute-set literals, dynamic
//! string-valued attribute names, static and dynamic string-valued
//! attribute selection, lexical `let` environments, simple and formal-set lambda
//! application, lazy `with` scope lookup, attrset update, thunk forcing, numeric
//! arithmetic, numeric and string/list comparisons, direct strict primops,
//! and scalar/string/function plus structural
//! list/attrset equality to weak head normal form, establishing the arena access
//! and diagnostic surface used by later slices for full string coercion,
//! first-class primitive operations, and derivation boundaries.
use base64::Engine as _;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use md5::{Digest as _, Md5};
use regex::bytes::{Regex, RegexBuilder};
use serde_json::Value as JsonValue;
use sha1::{Digest as _, Sha1};
use sha2::Sha512;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::OsStr,
    fmt, fs,
    io::{self, Cursor, Read, Write as _},
    os::unix::ffi::OsStrExt,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::UNIX_EPOCH,
};
use thiserror::Error;
use toml::{Value as TomlValue, value::Datetime as TomlDatetime};
use url::Url;
use xz2::read::XzDecoder;

use super::env::{
    EvalEnv, EvalEnvError, EvalEnvFrames, EvalFlatCapture, EvalFlatCaptureBuffer, EvalFrame,
    EvalScopedGlobalEnv, EvalWithEnv, EvalWithScope,
};
#[cfg(feature = "candidate_c_value")]
use super::heap::ImportEpochCensusFence;
use super::heap::{
    AllocationCollectorPollCopiedHeapFieldWrite, AllocationCollectorPollDirectHeapFieldWrite,
    AllocationCollectorPollForwardingInstallReport, AllocationCollectorPollHeapFieldWritebackSlot,
    AllocationCollectorPollMinorGcCommitBuffers, AllocationCollectorPollMinorGcCommitPlan,
    AllocationCollectorPollMinorGcOwnedCommitBuffers, AllocationCollectorPollMinorGcPlan,
    AllocationCollectorPollMinorGcRelocationDestinations,
    AllocationCollectorPollObjectByteCopyRequest, AllocationCollectorPollReferenceSlot,
    AllocationCollectorPollReferenceSource, AllocationCollectorPollReferenceWritebackPlan,
    AllocationCollectorPollReferenceWritebackReport, AllocationCollectorPollRootReferenceValue,
    AllocationCollectorPollRootValueWritebackSlot, AllocationCollectorPollRootWritebackPlan,
    AllocationCollectorPollRootWritebackReport, AllocationCollectorPollRootWritebackSlot,
    AllocationCollectorPollScan, EvalGcMode, EvalHeap, EvalHeapAttrsMetadata,
    EvalHeapCheapMemoryAdviceReport, EvalHeapCheapMemoryBudgetPlan, EvalHeapColdHashConsedValue,
    EvalHeapError, EvalHeapMemoryBudgetAction, EvalHeapResidentMemoryMode, EvalHeapSweepReport,
    EvalHeapTierBAdmissionReport, EvalHeapWorkerRegionPopReport, EvalLambda, EvalPrimOp,
    EvalPrimOpArg, EvalRootSet, EvalRootSource, EvalThunk, EvalThunkKind, HeapAllocationDomain,
    HeapEdgeSource, PreciseHeapScan,
};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
use super::heap::{DirectRootObservation, DirectRootRewriteError, DirectRootRewritePlan};
#[cfg(feature = "lifetime_cohort_probe")]
use super::heap::{
    LifetimeCohortCandidate, LifetimeCohortCandidateKind, LifetimeCohortCandidateObservation,
    LifetimeCohortCensus, LifetimeCohortMass, WeakHashConsPurgeReport,
    WeakHashConsTablePurgeReport,
};
use super::module::{EvalModuleId, EvalNodeRef};
use super::thunk::{DetachedForceClaim, ForceClaim, ForceError, ForceGuard, ThunkState};
use super::thunk_cas::ParallelThunkWorkerId;
use super::thunk_payload::{ParallelThunkPayloadError, TreeWalkParallelThunkCell};
use super::thunk_registry::ParallelForceCycleRegistry;
use super::whnf_tag::{WhnfTagFastPath, classify_whnf_tag_fast_path};
use crate::attrs::{
    AttrEntry, AttrError, AttrPosition, FlatAttrs,
    hamt::{HamtAttrs, HamtError, HamtMergeSummary},
    order::{AttrOrderError, AttrOrderTarget, collect_checked_lexicographic_keys},
    pic::{
        FlatSelectCache, FlatSelectError, FlatSelectOutcome, FlatSelectSource, HamtSelectCache,
        HamtSelectError, HamtSelectOutcome, HamtSelectPolicy, HamtSelectSource, ShapedSelectCache,
        ShapedSelectCacheState, ShapedSelectError, ShapedSelectOutcome, ShapedSelectSource,
        record::{RecordSelectCache, RecordSelectError, RecordSelectOutcome, RecordSelectSource},
    },
    repr::{
        AttrSetConstruction, AttrSetReprDecision, AttrSetReprKind, AttrSetReprPolicy,
        AttrSetReprValue, AttrSetReprValueError,
    },
    select::{
        AttrSelectError, AttrSelectOutcome, AttrSelectRepr, AttrSelectSource, AttrSelectTarget,
        select_slow,
    },
    shape::{
        ShapeError, ShapeHandle, ShapeId, ShapeTable, ShapeTableTransition, ShapedAttrs,
        ShapedAttrsError,
    },
    telemetry::AttrTelemetry,
};
use crate::cache::{
    CacheExprIdentity, CachedDerivationOutputPath, CachedDerivationOutputPaths,
    CachedExpressionValue, CachedParse, CutoffDecision, DemandNodeId, DirEntryInput,
    DurableBlake3Hash, EvalCacheRuntime, FileTypeForInput, ImpureInputFingerprint,
    ImpureInputIdentity, ImpureInputKind, ImpureInputMode, ImpureInputRevalidator,
    ImpureInputTraceSource, InputFingerprintError, MaterializationCostObservation,
    MaterializationCosts, MaterializationDecision, MemoizationDecision, MemoizationSubject,
    NixSha256Digest, ParseCache, ParseCacheError, ParseFileKey, PersistCache, PersistDiskLocation,
    PersistLatencyClass, PersistMaterialization, PersistNodeMetadataKey, PersistNodeTracePayload,
    ValueHash, lowered_ir_fingerprint,
};
#[cfg(test)]
use crate::compile::Strictness;
use crate::compile::{
    CapturePlan, DeadBindingReplacement, Escape, ExprFacts, FrameId, Ir, IrArena, IrAttrPathId,
    IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrDialectOp, IrId, IrKind,
    IrLowerOptions, IrNode, IrShape, IrShapeId, PromiseRegionOptions,
    PromiseRegionSymbolValidation, PromiseStatepointKind, ResolverOptions, ScopeResolver,
    analyze_call_target_candidates, analyze_known_call_targets, annotate_import_ir,
    dead_binding_elimination_plan, plan_promise_region, resolve,
};
#[cfg(feature = "lifetime_cohort_probe")]
use crate::heap::flat::FlatObjectKind;
use crate::heap::{
    AllocationRegionFacts, GcCardTable, GcCardTableClearReport, GcDirtyCard, GcHeapAddress,
    GenerationalGcError, GenerationalGcTier, HeapGeneration, HeapMemoryBudget, MinorGcCommitReport,
    MinorGcDestinationBases, MinorGcDestinationPlacementPlan, MinorGcForwardingSlot,
    MinorGcObjectByteCopyBuffer, MinorGcObjectCopyPlan, MinorGcOwnedDestinationStorage,
    MinorGcOwnedDestinationStorageCopyReport, MinorGcPlan, MinorGcPromotionPolicy,
    MinorGcSourceObjectBytes, MinorGcSurvivorAction, NurseryObjectLayout,
    ProcessResidentMemorySample, RegionEffect, RegionLifetime, RegionPlacement,
    RegionPlacementReason, RegionPlan, RegionRuntimeTier, RegionSharing, RememberedEdge,
    RememberedSet, RememberedSetEpoch, ResolvedValueGeneration,
};
#[cfg(feature = "nonmoving_reclaim_probe")]
use crate::heap::{PeakResidentMemoryScope, peak_resident_memory_bytes};
use crate::list::{NixList, NixListError};
#[cfg(test)]
use crate::runtime::alloc::RuntimeAllocationEntryPoint;
use crate::runtime::alloc::{AllocationCollectorPoll, GcStressPolicy, RuntimeAllocatorTier};
use crate::runtime::builtins::*;
use crate::string::{
    ContextElement, ContextKind, NixString, NixStringError, StringContext, try_clone_bytes,
};
use crate::syntax::{BinOpKind, Span, Symbol, SymbolTable, UnaryOpKind, parse_bytes_with_symbols};
#[cfg(feature = "lifetime_cohort_probe")]
use crate::value::HeapObject;
use crate::value::{Value, ValueTag};
use aos_nix_compat::drv_materialize::materialize_drv;
use aos_nix_dialect::{nix_lower, nix_lower_with_options};
mod builtins;
mod runtime_values;

// Type, helper, and error-enum definitions split into concern modules below;
// re-exported here so siblings (and the public path) keep resolving them.
mod api;
mod campaign_counters;
mod capture_on_demand;
mod capture_probe;
#[cfg(test)]
mod capture_validation;
#[cfg(feature = "collection_poll_probe")]
mod collection_poll;
mod constants;
mod error_kind;
mod errors;
#[cfg(feature = "collection_poll_probe")]
mod final_force_leaf_pmu;
mod native_continuation_shadow;
#[cfg(feature = "nested_nonmoving_retirement_probe")]
mod nested_nonmoving_retirement_probe;
#[cfg(feature = "collection_poll_probe")]
mod nested_nonmoving_safepoint_probe;
mod op_types;
mod options;
mod outcome;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
mod packed_mutator_root_stage;
#[cfg(feature = "packed_portal_cutover")]
mod packed_portal_cutover;
#[cfg(feature = "peak_ordinal_probe")]
mod peak_ordinal;
#[cfg(feature = "collection_poll_probe")]
mod restart_to_root_probe;
#[cfg(feature = "nested_nonmoving_retirement_probe")]
mod rotating_rollover_probe;
mod toml_normalize;
mod version;
#[cfg(feature = "collection_poll_probe")]
mod whole_demand_corridor_census;
#[cfg(feature = "collection_poll_probe")]
mod whole_demand_dispatcher;
#[cfg(feature = "young_increment_projection_probe")]
mod young_increment_projection_probe;
pub(crate) use constants::*;
mod config_types;
pub use config_types::*;
mod module_types;
pub(crate) use module_types::*;
mod fetch_types;
pub(crate) use fetch_types::*;
mod env_types;
pub(crate) use env_types::*;
mod derivation_types;
pub(crate) use api::{
    attr_path_segment_is_list_index, parse_attr_path_list_index,
    parse_attr_path_list_index_diagnostic,
};
pub(in crate::eval) use api::{
    eval_derivation_aterm_surfaces_with_options, eval_raw_bytes_with_evaluator_owned,
    eval_raw_bytes_with_post_render_tier_b_admission,
};
pub use api::{
    eval_instantiation_attr_path_owned_with_options_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache,
    eval_instantiation_attr_path_owned_with_options_source_realizer_eval_cache_and_engine,
    eval_number_raw_bytes, eval_number_raw_bytes_with_options, eval_raw_bytes,
    eval_raw_bytes_with_options, eval_raw_bytes_with_options_source, eval_whnf, eval_whnf_owned,
    eval_whnf_owned_with_options, eval_whnf_owned_with_options_and_realizer,
    eval_whnf_owned_with_options_realizer_and_eval_cache,
    eval_whnf_owned_with_options_realizer_eval_cache_and_engine, eval_whnf_with_options,
};
pub use campaign_counters::CampaignCounters;
pub use derivation_types::*;
pub use error_kind::TreeWalkErrorKind;
pub(crate) use errors::ArithmeticOp;
pub use errors::EvalErrorContext;
pub use errors::{EvalErrorLabel, EvalErrorSource, TreeWalkError};
pub(crate) use eval_regex_ere::{bracket_expression_end, translate_posix_ere};
pub(crate) use json_float::nlohmann_json_float_bytes;
pub(crate) use op_types::*;
pub use options::TreeWalkOptionsError;
pub use options::{BoundaryMemoOptions, MemoNetMode, MemoNetOptions, MemoOptions};
pub use options::{canonicalize_policy_path, normalize_absolute_path_bytes};
pub(crate) use options::{
    file_type_name, is_valid_store_path, join_path_literal, join_search_path,
    path_exists_requires_directory, path_is_under_root, path_without_trailing_path_markers,
    search_path_literal_lookup, search_path_suffix, store_path_root,
};
pub use outcome::{
    EvalDerivation, EvalGcStressBoundaryMinorGcCommitApplication,
    EvalGcStressBoundaryMinorGcCommitApplications, EvalGcStressBoundaryMinorGcCommitDryRun,
    EvalGcStressBoundaryMinorGcCommitDryRunSummary, EvalGcStressBoundaryMinorGcCommitPreflight,
    EvalGcStressBoundaryMinorGcCommitPreflights,
    EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit,
    EvalGcStressBoundaryMinorGcForwardingHeaderWrite,
    EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan,
    EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes,
    EvalGcStressBoundaryMinorGcLiveDestinationStorage,
    EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings,
    EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveObjectGeneration,
    EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    EvalGcStressBoundaryMinorGcLiveObjectGenerations,
    EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
    EvalGcStressBoundaryMinorGcObjectByteCopyApplication,
    EvalGcStressBoundaryMinorGcObjectGenerationWrite,
    EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
    EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport, EvalGcStressBoundaryMinorGcPlans,
    EvalGcStressBoundaryMinorGcReferenceWritebackApplication,
    EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    EvalGcStressBoundaryMinorGcRelocationDestinations, EvalGcStressBoundaryMinorGcRelocationPlan,
    EvalGcStressBoundaryMinorGcRelocationPlans,
    EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
    EvalGcStressBoundaryMinorGcRootWritebackWrite,
    EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport, EvalGcStressBoundaryScans,
    EvalOutcome, EvalStats, EvalTierBTransitionAdmissionApplyError,
    EvalTierBTransitionAdmissionPlan, EvalTierBTransitionAdmissionPlanError,
    EvalTierBTransitionDomain, EvalTierBTransitionDomainPreflight, EvalTierBTransitionPreflight,
    EvalTierBTransitionPreflightError, EvalTierBTransitionRequest, EvalTraceKind, EvalTraceOutput,
    EvalWarningOutput, IfdErrorDetail, IfdRealization, IfdRealizationError, IfdRealizer,
    MemoTierEvents,
};
pub(crate) use toml_normalize::normalize_toml_numeric_overflows;
pub(crate) use version::{
    SplitVersionRanges, base_name_range, compare_version_bytes, parse_drv_name_split,
};

/// A safe recursive evaluator for lowered IR.
#[derive(Debug)]
pub struct TreeWalk {
    modules: Vec<TreeWalkModule>,
    current_module: EvalModuleId,
    symbols: SymbolTable,
    heap: EvalHeap,
    /// The active lexical frame stack.
    ///
    /// Every production frame carries an immutable parent link, so capturing
    /// the shared suffix clones only its innermost head pointer.
    env: env_types::ActiveEvalFrames,
    /// Compact immutable outer prefix installed while a flat-captured closure
    /// runs. Frames pushed by the body remain in [`Self::env`].
    flat_env: Option<EvalFlatCapture>,
    /// Flat-plan closures awaiting the outermost binding publication boundary.
    pending_flat_captures: Vec<flat_capture::PendingFlatCapture>,
    /// Whether any nested binding assembly failed before publication.
    order_sensitive_binding_failed: bool,
    /// Outer assembly depth hidden while an eagerly elided thunk body runs.
    ///
    /// Publication still belongs to the physical outer scopes, but allocation
    /// planning must see the elided body as the demand-position evaluation
    /// that the removed thunk would have performed.
    order_sensitive_binding_planning_floor: usize,
    with_scopes: EvalWithEnv,
    scoped_globals: EvalScopedGlobalEnv,
    /// Opt-in capture-on-demand elision state for dynamic environments
    /// (RFC-0007 §P1). Default-inert; see [`capture_on_demand`].
    capture_on_demand: capture_on_demand::CaptureOnDemand,
    /// Default-off runtime-weighted Promise/PIR entry census.
    promise_region_census: Option<promise_region_census::PromiseRegionRuntimeCensus>,
    /// Compile-time-only projected duplicate-work census.
    #[cfg(feature = "maximal_laziness_probe")]
    maximal_laziness_census: Option<maximal_laziness_census::MaximalLazinessRuntimeCensus>,
    /// Compile-time-only whole-demand allocation/statepoint shadow census.
    #[cfg(feature = "demand_region_shadow_probe")]
    demand_region_shadow_probe: Option<demand_region_shadow_probe::DemandRegionShadowProbe>,
    /// Compile-time-only chronological allocation-cohort aggregate probe.
    #[cfg(feature = "lifetime_cohort_probe")]
    lifetime_cohort_probe: Option<lifetime_cohort_probe::LifetimeCohortProbe>,
    /// Compile-time-only all-object immutable-cohort packing projection.
    #[cfg(feature = "immutable_cohort_projection_probe")]
    immutable_cohort_projection_probe:
        Option<immutable_cohort_projection_probe::ImmutableCohortProbe>,
    /// Compile-time-only root-session continuation coverage shadow.
    #[cfg(feature = "root_continuation_probe")]
    root_continuation_probe: Option<root_continuation_probe::RootContinuationProbe>,
    /// Compile-time-only whole-demand suspended-dispatch coverage state.
    #[cfg(feature = "collection_poll_probe")]
    whole_demand_dispatcher: whole_demand_dispatcher::WholeDemandDispatcherRuntime,
    /// Compile-time-only restart-to-API eligibility falsifier.
    #[cfg(feature = "collection_poll_probe")]
    restart_to_root_probe: Option<restart_to_root_probe::RestartToRootProbe>,
    /// Default-off proof-only inventory for a nested nonmoving safepoint.
    #[cfg(feature = "collection_poll_probe")]
    nested_nonmoving_safepoint_probe:
        Option<nested_nonmoving_safepoint_probe::NestedNonmovingSafepointProbe>,
    /// Default-off report-only admission for one nested retirement ordinal.
    #[cfg(feature = "nested_nonmoving_retirement_probe")]
    nested_nonmoving_retirement_probe:
        Option<nested_nonmoving_retirement_probe::NestedNonmovingRetirementProbe>,
    /// Bounded read-only producer for the rotating-rollover checkpoint schedule.
    #[cfg(feature = "nested_nonmoving_retirement_probe")]
    rotating_rollover_probe: Option<rotating_rollover_probe::RotatingRolloverProbe>,
    /// Read-only packed-at-birth chronological increment projection.
    #[cfg(feature = "young_increment_projection_probe")]
    young_increment_projection_probe:
        Option<young_increment_projection_probe::YoungIncrementProjectionProbe>,
    /// Bounded proof-only roots and edge census for native continuations.
    #[cfg(feature = "collection_poll_probe")]
    native_continuation_shadow: Option<native_continuation_shadow::NativeContinuationShadow>,
    /// Cached exact-body admissions for the string-list deduplication canary.
    #[cfg(feature = "dedup_string_list_canary")]
    dedup_string_list_plans:
        HashMap<EvalNodeRef, Option<dedup_string_list_canary::DedupStringListPlan>>,
    /// Cached exact-fold admissions for the final-config trie canary.
    #[cfg(feature = "final_config_trie_canary")]
    final_config_trie_plans:
        HashMap<EvalNodeRef, Option<final_config_trie_canary::FinalConfigTriePlan>>,
    /// Cached source-independent admissions for the report-only option-map fold probe.
    #[cfg(feature = "option_map_fold_probe")]
    option_map_fold_probe_plans:
        HashMap<EvalNodeRef, Option<option_map_fold_probe::OptionMapFoldPlan>>,
    /// Ready-import-exclusive objects captured before the terminal demand window.
    #[cfg(feature = "ready_exclusive_probe")]
    ready_exclusive_window: Option<crate::eval::heap::ReadyExclusiveCensus>,
    options: TreeWalkOptions,
    stats: EvalStats,
    #[cfg(feature = "peak_ordinal_probe")]
    peak_ordinal_contexts: Vec<peak_ordinal::PeakOrdinalContext>,
    /// Default-off imported-root machine coverage and oracle-boundary counts.
    demand_machine_import_counters: demand_machine::DemandMachineImportCounters,
    /// Default-off inclusive coverage probe for the `lib/modules.nix` island.
    direct_island_probe: Option<direct_island_probe::DirectIslandProbe>,
    /// Process-wide environment capture counters observed at construction;
    /// `stats_snapshot` reports the movement since this baseline (doc 30 FV-0).
    campaign_env_baseline: super::env::capture_stats::EnvCaptureStats,
    attr_telemetry: AttrTelemetry,
    shape_table: Option<ShapeTable>,
    flat_select_caches: SelectCacheMap<(u32, u32, usize), FlatSelectCache>,
    shaped_select_caches: SelectCacheMap<(u32, u32, usize), ShapedSelectCache>,
    record_select_caches: SelectCacheMap<(u32, u32, usize), RecordSelectCache>,
    hamt_select_caches: SelectCacheMap<(u32, u32, usize), HamtSelectCache>,
    /// Resolved builtin per direct primop call site (module + IR node id).
    ///
    /// The lowered IR is immutable, so a `(module, node)` pair always names the
    /// same builtin; memoizing the resolution replaces a per-call name hash with
    /// an array index. See [`primop_builtin_cache`](self::primop_builtin_cache).
    primop_builtin_cache: primop_builtin_cache::PrimopBuiltinCache,
    /// Resolved layout per formal-set lambda pattern (module + pattern node id).
    ///
    /// A formal-set pattern's shape (formal names, defaults, alias slot, total
    /// slots) is fixed by its immutable IR node, so it is derived once and reused
    /// across every application of the lambda. See
    /// [`formal_set_layout_cache`](self::formal_set_layout_cache).
    formal_set_layout_cache: formal_set_layout_cache::FormalSetLayoutCache,
    /// Per-site resolved shapes for static attrset literals
    /// ([`AttrShapeMode::Record`] only): a static site's key sequence is
    /// fixed, so its transition-tree walk resolves once and later
    /// allocations at the site reuse the interned handle.
    static_literal_shapes: SelectCacheMap<(u32, u32), ShapeHandle>,
    attr_update_node_states: BTreeMap<AttrUpdateTelemetryNodeKey, AttrUpdateTelemetryState>,
    /// Whether `//` merges record per-merge attrset telemetry.
    ///
    /// The telemetry pipeline (shape census, representation-policy dispatch,
    /// and override-chain node states) re-walks every merge result and is
    /// consumed only by in-process measurement snapshots, so production
    /// evaluation disables it and takes the linear
    /// [`FlatAttrs::update_right_biased`] fast path instead. Enabled by
    /// default under `cfg(test)` and via the `AOS_NIX_ATTR_TELEMETRY`
    /// environment variable; both paths produce representation-identical
    /// attrset values.
    attr_update_telemetry_enabled: bool,
    trace_output: Vec<EvalTraceOutput>,
    warning_output: Vec<EvalWarningOutput>,
    impure_input_trace: Vec<ImpureInputFingerprint>,
    impure_input_trace_complete: bool,
    #[cfg(feature = "collection_poll_probe")]
    final_force_ifd_realizations: std::cell::Cell<u64>,
    force_cache_impure_trace_epoch: u64,
    active_memo_read_nodes: Vec<ActiveMemoReadNode>,
    active_derivation_trace_cursors: Vec<ImpureInputTraceCursor>,
    persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
    stderr: EvalStderr,
    find_file_cache: BTreeMap<FindFileCacheKey, FindFileCacheEntry>,
    find_file_cache_hits: usize,
    find_file_cache_misses: usize,
    /// Store paths already computed for coerced source paths, keyed by
    /// `(path bytes, recursive)` — the C++ Nix `EvalState::srcToStore`
    /// equivalent. Computing a source store path NAR-serializes and
    /// SHA-256-hashes the entire tree, so re-coercing the same path (the
    /// module system coerces shared source directories many times) must not
    /// re-hash it. Only plain coercions participate (no expected hash, no
    /// source filter — a filter changes the archived content, so filtered
    /// coercions always recompute). Like [`import_cache`](Self::import_cache),
    /// this assumes the filesystem is stable for the duration of one
    /// evaluation, the same assumption C++ Nix's process-wide map makes.
    source_store_string_cache: BTreeMap<(Vec<u8>, bool), Vec<u8>>,
    known_derivations: BTreeMap<nix_compat::store_path::StorePath<String>, KnownDerivation>,
    /// Cross-worker shared state for one parallel evaluation (L2-P3b).
    ///
    /// `Some` exactly while this evaluator participates in a parallel demand
    /// pool: the main worker between pool spawn and finish, and helper
    /// workers for their whole lifetime. Serial evaluation never sets it.
    shared: Option<Arc<parallel_demand::SharedEvalContext>>,
    /// Consumed prefix of the shared known-derivation log.
    shared_known_derivations_cursor: usize,
    /// Consumed prefix of the shared text-store log.
    shared_text_store_cursor: usize,
    /// Consumed prefix of the shared import-result log.
    shared_import_log_cursor: usize,
    /// Last observed [`parallel_demand::SharedEvalContext`] version.
    shared_version_seen: u64,
    import_cache: BTreeMap<PathBuf, ImportCacheEntry>,
    /// Strictly nested misses whose cache entries are currently `Evaluating`.
    ///
    /// This is evaluator-owned rather than represented by a borrowing guard so
    /// an explicit demand machine can suspend and resume import evaluation.
    active_import_cache_leases: Vec<ActiveImportCacheLease>,
    /// Last generation assigned to an import-cache lease token.
    next_import_cache_lease_generation: u64,
    /// Strictly nested imported-module contexts currently installed.
    active_import_module_leases: Vec<ActiveImportModuleLease>,
    /// Last generation assigned to an imported-module context lease.
    next_import_module_lease_generation: u64,
    /// Strictly nested ordinary thunk claims owned by explicit continuations.
    active_force_leases: Vec<ActiveForceLease>,
    /// Last generation assigned to an evaluator-owned force lease.
    next_force_lease_generation: u64,
    /// Tail-free Node work detached from ordinary blackholed flat thunks.
    #[cfg(feature = "collection_poll_probe")]
    active_node_work_leases: Vec<ActiveNodeWorkLease>,
    /// Test-only override for the default-off active Node detachment experiment.
    #[cfg(all(test, feature = "collection_poll_probe"))]
    active_node_work_detachment_test_enabled: bool,
    /// Typed-head work detached from its pool while the stable head is blackholed.
    ///
    /// A claimed typed head contains no scannable suspended-work pointer, so
    /// the evaluator owns the moved work here until publication or rollback.
    active_typed_thunk_work_leases: Vec<ActiveTypedThunkWorkLease>,
    /// Default-off generic packed-STG apply executor and its owned stacks.
    stg_apply_runtime: stg_apply_machine::StgApplyRuntime,
    /// Whether the default-off session evaluator currently owns control.
    stg_session_active: bool,
    /// Immutable exact-marker recipes keyed by generator closure identity.
    genlist_elem_at_add_one_plans: HashMap<u64, genlist_elem_at::GenListElemAtAddOneRecipe>,
    /// Stats-only static body classifications keyed by selected lambda code.
    genlist_selected_child_body_plans:
        HashMap<EvalNodeRef, force_shape_census::SelectedApplyBodyDescriptor>,
    /// Number of exact marker claims made by the session evaluator.
    stg_session_marker_claims: u64,
    /// Maximum compact marker-update depth reached by one session.
    stg_session_max_update_depth: usize,
    /// Strictly nested simple lambda calls owned by explicit continuations.
    active_lambda_call_leases: Vec<ActiveLambdaCallLease>,
    /// Last generation assigned to an evaluator-owned lambda-call lease.
    next_lambda_call_lease_generation: u64,
    /// Path prefixes confirmed to contain no symlink component during
    /// force-cache traceability checks. The Nix store is immutable for the
    /// duration of an evaluation, so `symlink_metadata` results are stable and
    /// can be memoized; imports under a shared store path would otherwise
    /// re-`lstat` every ancestor component on each resolution.
    import_traceable_nonsymlink_prefixes: HashSet<PathBuf>,
    /// Memoizes `import` path resolution keyed by the coerced request bytes.
    ///
    /// Resolving an `import` argument to its `(target, realpath)` pair requires
    /// an `fs::metadata` probe (directory promotion to `default.nix`) and an
    /// `fs::canonicalize` (realpath). The canonicalized realpath is the
    /// [`import_cache`](Self::import_cache) key, so both syscalls run *before*
    /// the value cache is consulted and would otherwise repeat on every import
    /// of an already-evaluated file. The filesystem is immutable for the
    /// duration of an evaluation, so the resolution is stable and cacheable.
    import_paths_cache: HashMap<Vec<u8>, (PathBuf, PathBuf)>,
    parse_cache: Option<ParseCache>,
    persist_cache: Option<PersistCache>,
    /// Opened secondary L2 disk locations in probe order (MEMO-2 §5.4).
    ///
    /// Populated alongside [`Self::persist_cache`] from
    /// `TreeWalkOptions::memo_disk_locations`; empty when none are configured
    /// or none opened. Import-time parse-artifact probes fall through to
    /// these after a primary miss and promote hits into the primary.
    persist_secondary_caches: Vec<(PersistLatencyClass, PersistCache)>,
    persist_cache_open_attempted: bool,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    // Cached "is any forced-expression cache observable" predicate, computed once
    // at construction. True when the in-memory eval cache runtime is enabled or a
    // persistent cache root is configured. When false, the per-force force-cache
    // subject/payload content hashing is pure waste (every observation is a
    // no-op), so the hot path skips it entirely. See `force_memoized_claimed_thunk`.
    force_cache_active: bool,
    // Per-worker, identity-keyed cache of finished force-cache payloads for heap
    // `List`/`Attrs` aggregates, keyed by heap address. Skips re-encoding shared
    // substructure on the persistent observe path. Sound only under Tier-A's
    // non-moving permanent lanes; see `eval_core::force_payload_memo` for the B2
    // relocation hazard and the run-boundary staleness bound.
    force_payload_memo: std::cell::RefCell<eval_core::ForcePayloadMemo>,
    import_parse_cache_hits: usize,
    import_parse_cache_misses: usize,
    text_store: BTreeMap<Vec<u8>, TextStoreEntry>,
    // In-process replacement for `nix-store --check-validity` subprocess spawns
    // during forced fetches: a lazily-opened read-only SQLite reader of the store
    // path database plus a per-run memo. Falls back to the subprocess when the
    // database cannot be read. See `store_validity`.
    store_validity_checker: StoreValidityChecker,
    ifd_realizer: Option<IfdRealizer>,
    call_depth: usize,
    order_sensitive_binding_depth: usize,
    active_call_argument_plans: Vec<call_summary::CallArgumentPlan>,
    active_composite_accumulator_depth: usize,
    active_root_eval_node: Option<IrId>,
    active_gc_stress_accumulator_allocation_node: Option<IrId>,
    active_gc_stress_primop_arg_root_admission_depth: usize,
    active_force_roots: Vec<Value>,
    active_primop_arg_roots: Vec<EvalPrimOpArg>,
    active_primop_arg_frames: Vec<ActivePrimopArgFrame>,
    transient_value_stack_roots: Vec<Value>,
    suspended_env_roots: Vec<SuspendedTreeWalkEnv>,
    thunk_resolve_remembered_set: RememberedSet,
    thunk_resolve_card_table: GcCardTable,
    // Effective Tier-B live-reclamation mode for this evaluation. Copied from
    // options at construction with the parallel quiescence pin applied, so the
    // force hot path reads one field instead of re-deriving the pin.
    gc_mode: EvalGcMode,
    // Worker-record count observed by the last quiescent sweep, for the
    // growth-threshold cadence.
    gc_records_at_last_sweep: u64,
    // Quiescent-sweep requests declined because the evaluator held transient
    // roots or an in-flight force (diagnostic counter).
    gc_sweeps_skipped_nonquiescent: u64,
    // The most recent quiescent sweep's cycle report, for stats surfaces.
    gc_last_sweep_report: Option<EvalHeapSweepReport>,
    // Lazy identity primops expose their returned argument thunk to strict consumers.
    // Keyed by thunk payload bits and used only for membership tests, so an
    // unordered `HashSet` gives O(1) probes on the per-force hot path.
    lazy_identity_thunks: HashSet<u64>,
    // Empty-list foldl' returns keep the initial accumulator lazy, but attr consumers
    // must still demand it when coercing to an attrset. A subset of
    // `lazy_identity_thunks`, likewise membership-only.
    lazy_foldl_initial_thunks: HashSet<u64>,
    // Type-erased tier-1 native-entry publish side-table, keyed by thunk payload
    // bits. Additive and off the force hot path: force never reads it. See
    // `tier1_publish` and `publish_tier1_slot`.
    tier1_publish_slots: HashMap<u64, OpaqueTier1Slot>,
    // Tier-1 native entries shared across every thunk instance of a def-site,
    // keyed by `(module_index << 32) | ir_root`. Tier-1 code is compiled per IR
    // body, so a hot def-site's published entry dispatches for all its instances.
    // Populated only when a `tier1_engine` promotes a body. See `Tier1Engine`.
    tier1_def_site_slots: HashMap<u64, OpaqueTier1Slot>,
    // Def-sites the tier-1 engine has permanently decided not to dispatch
    // (blacklisted or gated as delegate-only). Keyed by the def-site body's
    // `EvalNodeRef` so the force path can consult it with only a cheap
    // `EvalThunk::body_ref` field read, skipping the engine hook (and its heap
    // and side-table lookups) for a decided cold def-site's later instances.
    tier1_skipped_def_sites: HashSet<EvalNodeRef>,
    // Tier-2 compiled lambda entries shared across every closure instance of a
    // lambda def-site, keyed by `(module_index << 32) | body_ir_id`. Populated
    // only when a `tier1_engine` promotes a lambda body through the tier-2
    // apply seam. See `tier2_apply`.
    tier2_def_site_slots: HashMap<u64, OpaqueTier1Slot>,
    // Lambda def-sites the engine has permanently decided not to dispatch
    // through the tier-2 apply seam (blacklisted or gated), as a per-module
    // bit vector indexed by the lambda body's IR id. The apply path is far
    // hotter than the force path, so the decided check must not hash: two
    // indexed loads and a bit test keep the per-apply hook tax negligible on
    // apply-dominated workloads that promote nothing.
    tier2_skipped_def_sites: Vec<Box<[u64]>>,
    // The number of distinct decided (skipped) tier-2 def-sites, for
    // diagnostics; the bit vector itself has no cheap population count.
    tier2_skipped_def_site_total: usize,
    // Optional pluggable tier-1 JIT engine consulted once per claimed serial
    // force. `None` (the default) leaves the force path byte-for-byte unchanged.
    // Held by `Rc` so the force path can clone it out and release the field
    // borrow before handing the engine `&mut self`. See `Tier1Engine`.
    tier1_engine: Option<Rc<dyn Tier1Engine>>,
    // Shared cross-worker wait registry for parallel thunk forcing. Present
    // exactly when parallel thunk payloads are enabled; every parallel cell
    // allocated by this evaluator is bound to it so waiters can detect
    // cross-worker deadlock cycles before parking. Workers sharing one demand
    // graph must share one registry (see `set_parallel_force_registry`).
    parallel_force_registry: Option<Arc<ParallelForceCycleRegistry>>,
    // Per-worker in-thread content memo (MEMO-1 L0). `Some` exactly when
    // `MemoOptions` enables the L0 tier; `None` keeps the force path free of
    // any memo bookkeeping. See `memo` and `eval_core::memo`.
    memo_l0: Option<memo::MemoL0Table>,
    // Global admitted-key census under `AOS_NIX_MEMO_STATS`; shared by all
    // parallel workers and absent from ordinary parity/performance runs.
    memo_economics: Option<Arc<memo::MemoEconomicsCensus>>,
    // Worker-local raw-identity Ready-cell census under `AOS_NIX_MEMO_STATS`.
    // This shadow directory never serves hits or retains evaluator values.
    ready_cell_census: Option<memo::ReadyCellCensus>,
    // Opt-in one-way Ready-cell directory. Entries are weak thunk identities,
    // so construction is restricted to the monotonic serial GC-off heap.
    // Every hit rechecks that the source cell still has a cached value.
    ready_cell_directory: Option<memo::ReadyCellDirectory>,
    // Default-off, report-only exact-identity formal-set Pending/Ready census.
    // It retains integer keys and timing metadata only, never evaluator values.
    formal_set_ready_census: Option<formal_set_ready_census::FormalSetReadyCensus>,
    // Static direct-slot plans shared by the Ready-cell census and active
    // directory. Absent unless one of those opt-in modes is actually active.
    ready_cell_plans: Option<memo::ReadyCellPlanCache>,
    // Per-def-site static admission decisions for the content memo, computed
    // once per `(module, node)` body and reused by every later force of any
    // thunk instance of that def-site. This is the runtime realization of the
    // design's "admission flags on lowered nodes": non-admitted def-sites pay
    // one direct module index plus a module-local integer lookup per force.
    memo_def_sites: memo::MemoDefSiteTable,
    // Per-eval memo of captured values known to have no durable hash (keyed
    // by value payload bits). Purely advisory: a stale entry can only cause
    // a spurious memo decline. See `eval_core::memo`.
    memo_unhashable_values: HashSet<u64>,
    #[cfg(test)]
    tree_walk_list_wrapper_calls: usize,
    #[cfg(test)]
    gc_stress_permanent_root_allocation_dispatches: Vec<RuntimeAllocationEntryPoint>,
    /// Test-only one-shot panic injected inside typed detached-work evaluation.
    #[cfg(test)]
    panic_typed_thunk_body_once: bool,
    /// Test-only one-shot panic injected inside active packed evaluation.
    #[cfg(all(test, feature = "active_packed_thunk_probe"))]
    panic_active_packed_thunk_body_once: bool,
    // Test-mode FV-5 capture-plan validation state. `None` (the default)
    // keeps every hook a no-op; see `capture_validation`.
    #[cfg(test)]
    capture_plan_validation:
        Option<Box<std::cell::RefCell<capture_validation::CaptureValidationState>>>,
}

// The `impl TreeWalk` body is split across concern-focused submodules below.
// Each re-opens `impl TreeWalk` and shares private items via `use super::*;`.
#[cfg(feature = "collection_poll_probe")]
mod active_node_work_lease;
mod all_any_eq_island;
mod alloc_intern;
mod attr_repr_stats;
mod boundary_admission;
mod boundary_apply_hooks;
mod call_summary;
mod coerce_paths;
#[cfg(feature = "dedup_string_list_canary")]
mod dedup_string_list_canary;
mod demand_epoch_probe;
mod demand_machine;
#[cfg(feature = "demand_region_shadow_probe")]
mod demand_region_shadow_probe;
mod derivation_build;
mod derivation_serialize;
mod direct_island_probe;
mod eval_apply;
mod eval_codec;
mod eval_compare;
mod eval_core;
mod eval_derivation;
mod eval_hash;
mod eval_import;
mod eval_import_root_cache;
mod eval_impure_inputs;
mod eval_list_filter;
mod eval_list_group;
mod eval_list_map;
mod eval_load;
mod eval_numeric;
mod eval_path_ops;
mod eval_primop_apply;
mod eval_primop_bind;
mod eval_raw;
mod eval_regex;
mod eval_regex_ere;
mod eval_session;
mod eval_sort;
mod eval_source;
mod eval_stats;
mod eval_trace;
#[cfg(feature = "lifetime_cohort_probe")]
mod exec176_weak_purge;
mod fetch_git_clone;
mod fetch_git_store;
mod fetch_git_tree;
mod fetch_tree_access;
mod fetch_tree_args;
mod fetch_tree_forge;
#[cfg(feature = "final_config_trie_canary")]
mod final_config_trie_canary;
mod flake_git;
mod flake_ref;
mod flat_capture;
mod force_shape_census;
mod formal_set_layout_cache;
mod formal_set_ready_census;
mod gc_sweep;
mod genlist_elem_at;
#[cfg(feature = "immutable_cohort_projection_probe")]
mod immutable_cohort_projection_probe;
mod import_persist_locations;
mod json_float;
mod lambda_call_lease;
#[cfg(feature = "lifetime_cohort_probe")]
mod lifetime_cohort_probe;
#[cfg(feature = "maximal_laziness_probe")]
mod maximal_laziness_census;
mod memo;
#[cfg(feature = "option_map_fold_probe")]
mod option_map_fold_probe;
mod parallel_demand;
mod parallel_import;
mod parallel_shape;
mod pkg_boundary_probe;
mod primop_builtin_cache;
mod promise_region_census;
mod region;
#[cfg(test)]
mod region_machine;
mod relocation_identity;
#[cfg(feature = "root_continuation_probe")]
mod root_continuation_probe;
mod runtime_alloc;
mod safepoint_roots;
mod select_cache_hash;
mod session_machine;
mod speculation;
mod stg_apply_machine;
#[cfg(feature = "candidate_c_value")]
mod terminal_permanent_publication;
mod tier1_dispatch;
mod typed_thunk_work_lease;
#[cfg(feature = "collection_poll_probe")]
use active_node_work_lease::ActiveNodeWorkLease;
use select_cache_hash::SelectCacheMap;
use typed_thunk_work_lease::ActiveTypedThunkWorkLease;
mod serialize_xml;
mod store_validity;
use store_validity::StoreValidityChecker;
mod fold_genlist;
mod tier1_publish;
pub use tier1_publish::{
    MixedReadyCallActivation, MixedReadyCallDecision, MixedReadyCallHook, MixedReadyCallToken,
    OpaqueTier1Slot, Tier1Engine, Tier1ForceHook, Tier2AllAnyHook, Tier2ApplyHook, Tier2FilterHook,
    Tier2FoldHook,
};
mod tier2_apply;
pub use eval_impure_inputs::{
    canonicalize_cacheable_input_trace, revalidate_cacheable_input_trace,
};
pub use gc_sweep::TreeWalkGcSweepError;
pub use safepoint_roots::{
    TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
    TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointMinorGcRootWritebackReport,
    TreeWalkSafepointRootError, TreeWalkSafepointRootWritebackError, TreeWalkSafepointScanError,
};
#[cfg(test)]
mod tests;
