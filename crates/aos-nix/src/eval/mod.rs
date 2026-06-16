//! Safe tree-walk evaluator components.
//!
//! Phase 1 grows the permanent correctness oracle here. The first pieces are the
//! serial thunk state machine, typed heap registry, and tree-walk entry point;
//! later slices add environments, closures, builtins, and the recursive IR
//! interpreter.

pub mod heap;
pub mod thunk;
pub mod tree_walk;

pub use heap::{EvalHeap, EvalHeapError};
pub use thunk::{ForceClaim, ForceError, ForceGuard, ThunkCell, ThunkState};
pub use tree_walk::{TreeWalk, TreeWalkError, TreeWalkErrorKind, eval_whnf};
