//! Safe tree-walk evaluator components.
//!
//! Phase 1 grows the permanent correctness oracle here. The first piece is the
//! serial thunk state machine; later slices add environments, closures, builtins,
//! and the recursive IR interpreter.

pub mod thunk;

pub use thunk::{ForceClaim, ForceError, ForceGuard, ThunkCell, ThunkState};
