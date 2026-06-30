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
pub mod thunk;
pub mod tree_walk;

pub use env::{EvalEnv, EvalEnvError, EvalFrame, EvalWithEnv, EvalWithScope};
pub use heap::{EvalHeap, EvalHeapError, EvalLambda, EvalThunk};
pub use internal_diff::{
    InternalDiffError, InternalDiffReport, InternalDiffTier, compare_raw_with_oracle,
};
pub use module::{EvalModuleId, EvalNodeRef};
pub use thunk::{
    DisabledThunkResolveBarrier, ForceClaim, ForceError, ForceGuard, ThunkCell,
    ThunkResolveBarrier, ThunkState,
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
