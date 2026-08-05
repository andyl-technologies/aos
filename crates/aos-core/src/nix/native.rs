//! Native Nix evaluator seam used by on-host configuration evaluation.
//!
//! This module deliberately exposes only the stable evaluator handle and its
//! policy types. Store realization remains owned by the existing Nix CLI seam;
//! the native evaluator is eval-only and has no realizer configured.

pub use aos_nix::eval::{EvalMode, TreeWalkOptions};
pub use aos_nix::heap::HeapMemoryBudget;
pub use aos_nix::{
    NativeConflictDef, NativeEvalError, NativeEvalOutput, NativeMissingOption,
    NativeMissingOptionKind, NativeResourceLimit, NixNative, OptionAccess, OptionAccessKind,
    OptionGraph,
};
