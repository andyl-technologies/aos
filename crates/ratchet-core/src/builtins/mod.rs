//! Builtin declarations shared by scope resolution and runtime dispatch.
//!
//! Each builtin marker type implements [`BuiltinDefinition`] with its static
//! execution strategy, documentation, top-level name policy, and executor
//! entrypoints. The execution strategy provides default direct-lowering and
//! first-class arity, and custom builtins can override those fields or runtime
//! entrypoints in their definition impl. The declaration macro publishes those
//! typed definitions as both the ordered `builtins` attrset inventory and the
//! generated exact-name lookup used by evaluator dispatch and frontend passes.
//!
//! The implementation is split across submodules:
//!
//! - `macros` — the declaration macros consumed by the inventory.
//! - `declarations` — the `define_builtins!` invocation and generated `BUILTINS` registry.
//! - `demand` — the per-builtin argument demand signatures used by strictness analysis.
//! - `types` — the declaration record types, executor trait, and registry.
//! - `docs` — the short user-facing documentation values.
//! - `lookup` — the compile-time perfect-hash name lookup table.

pub(super) use crate::syntax::{Span, Symbol};
pub(super) use crate::{IrId, IrNode};

#[macro_use]
mod macros;

mod declarations;
mod demand;
mod docs;
mod lookup;
mod types;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_metadata;

pub use declarations::{BUILTINS, BuiltinKind, BuiltinLookup};
pub use demand::{ArgDemand, DemandSignature, demand_signature};
pub use docs::*;
pub use lookup::BuiltinLookupTable;
pub use types::BuiltinDefinition;
pub use types::{
    Builtin, BuiltinAvailability, BuiltinCall, BuiltinDirect, BuiltinEffect, BuiltinExecution,
    BuiltinExecutor, BuiltinNameScope, BuiltinRegistry, DirectBinaryPrimOp,
    NativeCliFallbackFeature, StrictBinaryPrimOp, StrictTernaryPrimOp, StrictUnaryPrimOp,
    TraceMode,
};

/// The C++ Nix version whose observable builtin surface this evaluator targets.
pub const PINNED_NIX_VERSION: &[u8] = b"2.24.12";

/// The Nix language version reported by the pinned C++ Nix evaluator.
pub const PINNED_NIX_LANG_VERSION: i64 = 6;

/// Returns direct lowering behavior for a builtin name.
pub fn direct_builtin(name: &[u8]) -> Option<BuiltinDirect> {
    BUILTINS.direct(name)
}

/// Returns the declaration for a builtin name.
pub fn lookup_builtin(name: &[u8]) -> Option<Builtin> {
    BUILTINS.lookup(name)
}

/// Returns whether `name` is a builtin attribute known to this evaluator.
pub fn is_known_builtin_attr(name: &[u8]) -> bool {
    BUILTINS.is_known_attr(name)
}

/// Returns whether `name` is a top-level Nix name that active `with` scopes cannot shadow.
pub fn is_unshadowable_global_name(name: &[u8]) -> bool {
    BUILTINS.is_unshadowable_global_name(name)
}
