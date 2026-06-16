//! Safe tree-walk evaluator components.
//!
//! Phase 1 grows the permanent correctness oracle here. The first pieces are the
//! serial thunk state machine and the scalar-literal tree-walk entry point; later
//! slices add environments, closures, builtins, and the recursive IR interpreter.

pub mod thunk;
pub mod tree_walk;

pub use thunk::{ForceClaim, ForceError, ForceGuard, ThunkCell, ThunkState};
pub use tree_walk::{TreeWalk, TreeWalkError, TreeWalkErrorKind, eval_whnf};
