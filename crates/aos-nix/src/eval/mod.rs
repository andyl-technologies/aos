//! Safe tree-walk evaluator components.
//!
//! Phase 1 grows the permanent correctness oracle here. The first pieces are the
//! serial thunk state machine, typed heap registry, lexical environment frames,
//! simple closure records, and tree-walk entry point; later slices add builtins
//! and the recursive IR interpreter.

pub mod env;
pub mod heap;
pub mod thunk;
pub mod tree_walk;

pub use env::{EvalEnv, EvalEnvError, EvalFrame};
pub use heap::{EvalHeap, EvalHeapError, EvalLambda, EvalThunk};
pub use thunk::{ForceClaim, ForceError, ForceGuard, ThunkCell, ThunkState};
pub use tree_walk::{
    EvalOutcome, TreeWalk, TreeWalkError, TreeWalkErrorKind, eval_whnf, eval_whnf_owned,
};
