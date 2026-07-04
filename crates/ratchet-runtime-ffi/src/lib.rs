//! Unsafe C ABI wrappers for Ratchet runtime helpers.
//!
//! This crate owns the narrow runtime FFI boundary needed by native execution
//! tiers. Safe evaluator crates such as `ratchet-oracle` keep `unsafe_code`
//! denied; this crate instead uses `unsafe_op_in_unsafe_fn` so each raw pointer
//! operation remains explicit and reviewable.
//!
//! Current coverage is intentionally small:
//!
//! ```text
//! ratchet_runtime_ffi::env
//!   aos_env_get success-path wrapper for the frozen `(env, slot) -> Value` ABI
//! ratchet_runtime_ffi::force
//!   aos_force WHNF fast-path wrapper for the frozen `(rt, Value) -> Value` ABI
//! ratchet_runtime_ffi::safety
//!   unsafe-boundary manifest and source-token allowlist
//! ```
//!
//! The wrappers here are not yet sufficient for final JIT registration. They
//! cover success-path ABI shape and process-local address metadata for focused
//! tests, while evaluator trap/error transfer remains an explicit blocker before
//! `aos-nix` can treat these symbols as complete native exports.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod env;
pub mod force;
pub mod safety;

pub use safety::{
    RUNTIME_FFI_SAFETY_COMMENT_PREFIX, RUNTIME_FFI_UNSAFE_CRATE_LINT,
    RuntimeFfiInnateUnsafeOperation, RuntimeFfiUnsafeDiscipline, runtime_ffi_unsafe_discipline,
};
