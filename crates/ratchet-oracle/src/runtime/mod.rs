//! Runtime support tables shared by evaluator tiers.
//!
//! The Phase-1 tree-walk oracle owns execution. The builtin declaration list,
//! name lookup, and direct-lowering classification — the metadata that scope
//! resolution, static `builtins ? name` checks, and executor dispatch must all
//! agree on — live in [`crate::compile::builtins`] so the frontend depends on
//! no concrete evaluator. This module re-exports that metadata layer under its
//! historical `crate::runtime::builtins` path for the runtime tiers.

pub mod alloc;
pub mod allocation_values;
pub mod apply;
pub mod attr;
pub mod barrier;
pub mod env;
pub mod forcing;
pub mod helpers;

pub use crate::compile::builtins;
