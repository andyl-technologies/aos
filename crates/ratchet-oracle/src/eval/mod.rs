//! Safe tree-walk evaluator components.
//!
//! Phase 1 grows the permanent correctness oracle here. The first pieces are the
//! serial thunk state machine, typed heap registry, lexical environment frames,
//! simple closure records, and tree-walk entry point; later slices add builtins
//! and the recursive IR interpreter. The internal differential harness compares
//! later optimized tiers against the tree-walk oracle in test and fuzz builds.

pub mod env;
pub mod heap;
pub mod internal_diff;
pub mod module;
pub mod parallel;
pub mod parallel_failure;
pub mod parallel_heap;
pub mod parallel_output;
pub mod thunk;
pub mod thunk_cas;
pub mod thunk_lowering;
pub mod thunk_payload;
pub mod thunk_wait;
pub mod tree_walk;
pub mod whnf_tag;

pub use env::{EvalEnv, EvalEnvError, EvalFrame, EvalWithEnv, EvalWithScope};
pub use heap::{EvalHeap, EvalHeapError, EvalLambda, EvalThunk};
pub use internal_diff::{
    InternalDiffError, InternalDiffReport, InternalDiffTier, compare_raw_with_oracle,
};
pub use module::{EvalModuleId, EvalNodeRef};
pub use parallel::{
    ParallelReadyWorkError, ParallelReadyWorkExecution, ParallelReadyWorkQueues,
    ParallelReadyWorkStep, ParallelTaskExecution, ParallelTaskPlacement, ParallelTopLevelError,
    ParallelTopLevelExecutionReport, ParallelTopLevelSeedPlan, ParallelWorkerExecutionReport,
    execute_parallel_top_level, parallel_ready_work_queues, parallel_top_level_seed_plan,
};
pub use parallel_failure::{
    ParallelFailurePolicy, ParallelFailureWorkerReport, ParallelFallibleTopLevelError,
    ParallelFallibleTopLevelReport, ParallelTaskOutcome, execute_parallel_top_level_fallible,
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
    ParallelThunkPayloadWait, ParallelThunkPayloadWorkWait, ParallelThunkTerminalPayload,
    ParallelThunkTerminalStatus, TreeWalkParallelThunkCell, TreeWalkParallelThunkForceOutcome,
    TreeWalkParallelThunkForceWorkOutcome, TreeWalkParallelThunkGuard, TreeWalkParallelThunkWait,
    TreeWalkParallelThunkWorkWait,
};
pub use thunk_wait::{
    ParallelThunkContentionReport, ParallelThunkReadyWork, ParallelThunkWait,
    ParallelThunkWaitCell, ParallelThunkWaitError, ParallelThunkWaitGuard, ParallelThunkWaitStats,
    ParallelThunkWorkWait,
};
pub use tree_walk::{
    EvalDerivation, EvalErrorLabel, EvalErrorSource, EvalMode, EvalOutcome, EvalStats,
    IfdErrorDetail, IfdRealization, IfdRealizationError, IfdRealizer, TreeWalk, TreeWalkError,
    TreeWalkErrorKind, TreeWalkOptions, TreeWalkOptionsError,
    eval_instantiation_attr_path_owned_with_options_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache,
    eval_number_raw_bytes, eval_number_raw_bytes_with_options, eval_raw_bytes,
    eval_raw_bytes_with_options, eval_raw_bytes_with_options_source, eval_whnf, eval_whnf_owned,
    eval_whnf_owned_with_options, eval_whnf_owned_with_options_and_realizer,
    eval_whnf_owned_with_options_realizer_and_eval_cache, eval_whnf_with_options,
};
pub use whnf_tag::{
    CheckedWhnfTagFastPath, WhnfTagFastPath, checked_whnf_tag_fast_path,
    classify_whnf_tag_fast_path,
};
