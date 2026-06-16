//! Runtime support tables shared by evaluator tiers.
//!
//! The Phase-1 tree-walk oracle owns execution, while this module owns runtime
//! metadata that multiple stages must agree on. Keeping builtin names here lets
//! scope resolution, static `builtins ? name` checks, and executor dispatch use
//! the same declaration list.

pub(crate) mod builtins;
