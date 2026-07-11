//! Safe tree-walk evaluator components.
//!
//! Phase 1 grows the permanent correctness oracle here. The first pieces are the
//! serial thunk state machine, typed heap registry, lexical environment frames,
//! simple closure records, and tree-walk entry point; later slices add builtins
//! and the recursive IR interpreter. The internal differential harness compares
//! later optimized tiers against the tree-walk oracle in test and fuzz builds.

pub mod env;
pub mod gc_audit;
pub mod gc_conformance;
pub mod gc_measurement;
pub mod heap;
pub mod internal_diff;
pub mod module;
pub mod parallel;
pub mod parallel_audit;
pub mod parallel_chase_lev;
pub mod parallel_failure;
pub mod parallel_force;
pub mod parallel_heap;
pub mod parallel_output;
pub mod parallel_tree_walk;
pub mod thunk;
pub mod thunk_cas;
pub mod thunk_lowering;
pub mod thunk_payload;
pub mod thunk_registry;
pub mod thunk_wait;
pub mod tree_walk;
pub mod whnf_tag;

pub use env::{EvalEnv, EvalEnvError, EvalFrame, EvalWithEnv, EvalWithScope};
pub use gc_audit::{
    GcSafetyAuditInvocation, GcSafetyAuditLowerStage, GcSafetyAuditManifest,
    GcSafetyAuditManifestError, GcSafetyAuditScope, GcSafetyAuditSmokeError,
    GcSafetyAuditSmokeReport, GcSafetyAuditTarget, GcSafetyAuditTool, gc_safety_audit_invocations,
    gc_safety_audit_manifest, run_gc_safety_audit_gc_stress_smoke,
    run_gc_safety_audit_safe_tree_walk_smoke, validate_gc_safety_audit_manifest,
};
pub use gc_conformance::{
    GcConformanceCaseError, GcConformanceCaseReport, GcConformanceInvocation,
    GcConformanceLowerStage, GcConformanceManifest, GcConformanceManifestError, GcConformanceScope,
    GcConformanceSmokeError, GcConformanceSmokeReport, GcConformanceTarget, RawRenderMode,
    compare_gc_conformance_tier_a_tier_b_raw_bytes_source, gc_conformance_invocations,
    gc_conformance_manifest, run_gc_conformance_tier_a_tier_b_drv_bytes_smoke,
    run_gc_conformance_tier_a_tier_b_raw_bytes_smoke, validate_gc_conformance_manifest,
};
pub use gc_measurement::{
    HeapGcMeasurementId, HeapGcMeasurementInvocation, HeapGcMeasurementLowerStage,
    HeapGcMeasurementManifest, HeapGcMeasurementManifestError, HeapGcMeasurementScope,
    HeapGcMeasurementSmokeError, HeapGcMeasurementSmokeReport, HeapGcMeasurementTarget,
    heap_gc_measurement_invocations, heap_gc_measurement_manifest,
    run_heap_gc_measurement_m12_cons_table_sizing_smoke,
    run_heap_gc_measurement_m14_region_vs_generational_smoke,
    run_heap_gc_measurement_qg_per_invocation_budget_smoke, validate_heap_gc_measurement_manifest,
};
pub use heap::{EvalHeap, EvalHeapError, EvalLambda, EvalThunk};
pub use internal_diff::{
    InternalDiffError, InternalDiffReport, InternalDiffTier, compare_raw_with_oracle,
};
pub use module::{EvalModuleId, EvalNodeRef};
pub use parallel::{
    ParallelChaseLevReadyWorkQueue, ParallelChaseLevReadyWorkQueues, ParallelReadyWorkError,
    ParallelReadyWorkExecution, ParallelReadyWorkParkPreflight, ParallelReadyWorkParkReadiness,
    ParallelReadyWorkParkReadinessError, ParallelReadyWorkPoll, ParallelReadyWorkQueues,
    ParallelReadyWorkStep, ParallelReadyWorkWait, ParallelReadyWorkWaitError,
    ParallelTaskExecution, ParallelTaskPlacement, ParallelTopLevelError,
    ParallelTopLevelExecutionReport, ParallelTopLevelSeedPlan, ParallelWorkerExecutionReport,
    claim_or_poll_ready_then_wait, execute_parallel_top_level,
    execute_parallel_top_level_chase_lev, parallel_chase_lev_ready_work_queues,
    parallel_ready_work_queues, parallel_top_level_seed_plan,
};
pub use parallel_audit::{
    ParallelRuntimeAuditInvocation, ParallelRuntimeAuditLowerStage, ParallelRuntimeAuditManifest,
    ParallelRuntimeAuditManifestError, ParallelRuntimeAuditScope, ParallelRuntimeAuditSmokeError,
    ParallelRuntimeAuditSmokeReport, ParallelRuntimeAuditStandardMatrixSmokeReport,
    ParallelRuntimeAuditTarget, ParallelRuntimeAuditTool, parallel_runtime_audit_invocations,
    parallel_runtime_audit_manifest, run_parallel_audit_parallel_tree_walk_drv_smoke,
    run_parallel_audit_parallel_tree_walk_drv_standard_matrix_smoke,
    run_parallel_audit_parallel_tree_walk_raw_smoke,
    run_parallel_audit_safe_tree_walk_oracle_smoke, validate_parallel_runtime_audit_manifest,
};
pub use parallel_chase_lev::{
    ParallelChaseLevTake, ParallelChaseLevTask, ParallelChaseLevTaskSource,
    ParallelChaseLevTaskTake, ParallelChaseLevWorkerQueue, ParallelChaseLevWorkerQueues,
    parallel_chase_lev_worker_queues,
};
pub use parallel_failure::{
    ParallelFailurePolicy, ParallelFailureWorkerReport, ParallelFallibleTaskContext,
    ParallelFallibleTopLevelError, ParallelFallibleTopLevelReport, ParallelTaskOutcome,
    execute_parallel_top_level_fallible, execute_parallel_top_level_fallible_chase_lev,
    execute_parallel_top_level_fallible_chase_lev_with_worker,
    execute_parallel_top_level_fallible_with_worker,
};
pub use parallel_force::{
    ParallelSharedForceError, ParallelSharedForceWorkerReport, ParallelSharedGraphBody,
    ParallelSharedGraphForcer, force_shared_parallel_roots, infinite_recursion_error,
    shared_parallel_thunk_cells,
};
pub use parallel_heap::{
    ParallelHashConsCandidate, ParallelHashConsMerge, ParallelHashConsMergeDecision,
    ParallelHashConsMergeError, ParallelHashConsMergeOutcome, ParallelNurseryOwnershipError,
    ParallelNurseryOwnershipMode, ParallelTaskNurseryExecution, ParallelTaskNurseryOwnership,
    ParallelTaskNurseryOwnershipPlan, ParallelWorkerNursery, ParallelWorkerNurseryAssignment,
    ParallelWorkerNurseryPlan, merge_parallel_hash_cons_candidates,
    parallel_task_nursery_ownership_from_fallible_top_level_report,
    parallel_task_nursery_ownership_from_top_level_report, parallel_task_nursery_ownership_plan,
    parallel_worker_nursery_plan,
};
pub use parallel_output::{
    ParallelDrvOutput, ParallelOutputCollation, ParallelOutputDeterminismError,
    ParallelOutputDifferentialError, ParallelOutputDifferentialReport, ParallelOutputFragment,
    ParallelOutputTaskResult, collate_parallel_output_fragments,
    compare_parallel_output_across_worker_counts, parallel_drv_output_content_sha256,
};
pub use parallel_tree_walk::{
    ParallelTreeWalkCanonicalError, ParallelTreeWalkCanonicalOutcome,
    ParallelTreeWalkDifferentialError, ParallelTreeWalkDifferentialReport,
    ParallelTreeWalkDrvDifferentialError, ParallelTreeWalkDrvDifferentialReport,
    ParallelTreeWalkDrvEvaluation, ParallelTreeWalkDrvEvaluationError,
    ParallelTreeWalkDrvEvaluationReport, ParallelTreeWalkEvaluationError,
    ParallelTreeWalkRawEvaluation, ParallelTreeWalkRawEvaluationReport, ParallelTreeWalkRoot,
    ParallelTreeWalkRootSource, ParallelTreeWalkTopLevelError, ParallelTreeWalkWorkerHeapReport,
    ParallelTreeWalkWorkerHeapSummary,
    compare_parallel_tree_walk_drv_outputs_chase_lev_across_worker_counts,
    compare_parallel_tree_walk_drv_outputs_chase_lev_standard_worker_counts,
    compare_parallel_tree_walk_raw_across_worker_counts,
    compare_parallel_tree_walk_raw_chase_lev_across_worker_counts,
    eval_drv_outputs_parallel_chase_lev_top_level_roots,
    eval_raw_bytes_parallel_chase_lev_top_level, eval_raw_bytes_parallel_chase_lev_top_level_roots,
    eval_raw_bytes_parallel_top_level, eval_raw_bytes_parallel_top_level_roots,
    parallel_tree_walk_standard_differential_worker_counts,
    summarize_parallel_tree_walk_drv_worker_heaps, summarize_parallel_tree_walk_raw_worker_heaps,
};
pub use thunk::{
    DisabledThunkResolveBarrier, ForceClaim, ForceError, ForceGuard, ThunkCell,
    ThunkResolveBarrier, ThunkState,
};
pub use thunk_cas::{
    PARALLEL_THUNK_AWAIT_MARK_FAILURE_ORDERING, PARALLEL_THUNK_AWAIT_MARK_SUCCESS_ORDERING,
    PARALLEL_THUNK_CLAIM_FAILURE_ORDERING, PARALLEL_THUNK_CLAIM_SUCCESS_ORDERING,
    PARALLEL_THUNK_MAX_WORKER_ID, PARALLEL_THUNK_STATE_LOAD_ORDERING,
    PARALLEL_THUNK_TERMINAL_PUBLISH_FAILURE_ORDERING,
    PARALLEL_THUNK_TERMINAL_PUBLISH_SUCCESS_ORDERING, ParallelThunkAwait, ParallelThunkClaim,
    ParallelThunkClaimGuard, ParallelThunkMemoryOrderingAudit, ParallelThunkMemoryOrderingError,
    ParallelThunkMemoryOrderingRequirement, ParallelThunkMemoryOrderingRole, ParallelThunkPublish,
    ParallelThunkState, ParallelThunkStateError, ParallelThunkStateWord,
    ParallelThunkTerminalState, ParallelThunkWorkerId, validate_parallel_thunk_memory_ordering,
};
pub use thunk_lowering::{
    TreeWalkOmittedThunk, TreeWalkThunkAllocationContext, TreeWalkThunkAllocationError,
    TreeWalkThunkAllocationPlan, TreeWalkThunkElision, TreeWalkThunkUpdateReason,
    TreeWalkThunkUpdateSlot, tree_walk_thunk_allocation_plan,
};
pub use thunk_payload::{
    ParallelThunkPayloadCell, ParallelThunkPayloadError, ParallelThunkPayloadGuard,
    ParallelThunkPayloadReadyWorkError, ParallelThunkPayloadWait, ParallelThunkPayloadWorkWait,
    ParallelThunkTerminalPayload, ParallelThunkTerminalStatus, TreeWalkParallelThunkCell,
    TreeWalkParallelThunkForceOutcome, TreeWalkParallelThunkForcePollOutcome,
    TreeWalkParallelThunkForceWorkOutcome, TreeWalkParallelThunkGuard, TreeWalkParallelThunkWait,
    TreeWalkParallelThunkWorkWait,
};
pub use heap::{EvalGcMode, EvalHeapSweepReport};
pub use thunk_registry::{ParallelForceCycleRegistry, ParallelForceWaitRegistration};
pub use thunk_wait::{
    ParallelThunkContentionReport, ParallelThunkReadyWork, ParallelThunkReadyWorkWaitError,
    ParallelThunkWait, ParallelThunkWaitCell, ParallelThunkWaitError, ParallelThunkWaitGuard,
    ParallelThunkWaitStats, ParallelThunkWorkWait,
};
pub use tree_walk::{
    AttrShapeMode, CampaignCounters, EvalDerivation, EvalErrorLabel, EvalErrorSource, EvalMode,
    EvalOutcome,
    EvalStats,
    IfdErrorDetail, IfdRealization, IfdRealizationError, IfdRealizer, MemoNetMode,
    MemoNetOptions, MemoOptions, MemoTierEvents,
    OpaqueTier1Slot, Tier1Engine, Tier1ForceHook, Tier2AllAnyHook, Tier2ApplyHook, Tier2FilterHook,
    Tier2FoldHook,
    TreeWalk,
    TreeWalkError,
    TreeWalkErrorKind,
    TreeWalkOptions,
    TreeWalkOptionsError, canonicalize_cacheable_input_trace,
    eval_instantiation_attr_path_owned_with_options_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache,
    eval_instantiation_attr_path_owned_with_options_source_realizer_eval_cache_and_engine,
    eval_number_raw_bytes, eval_number_raw_bytes_with_options, eval_raw_bytes,
    eval_raw_bytes_with_options, eval_raw_bytes_with_options_source, eval_whnf, eval_whnf_owned,
    eval_whnf_owned_with_options, eval_whnf_owned_with_options_and_realizer,
    eval_whnf_owned_with_options_realizer_and_eval_cache,
    eval_whnf_owned_with_options_realizer_eval_cache_and_engine, eval_whnf_with_options,
    revalidate_cacheable_input_trace,
};
pub use whnf_tag::{
    CheckedWhnfTagFastPath, WhnfTagFastPath, checked_whnf_tag_fast_path,
    classify_whnf_tag_fast_path,
};
