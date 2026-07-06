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
//! ratchet_runtime_ffi::alloc
//!   aos_alloc_* trap-only wrappers for frozen pointer-returning allocation ABIs
//! ratchet_runtime_ffi::env
//!   aos_env_get success-path wrapper for the frozen `(env, slot) -> Value` ABI
//! ratchet_runtime_ffi::force
//!   aos_blackhole_check, aos_force, and aos_force_deep context-decoding
//!   success-path wrappers for frozen `(rt, Value)` forcing ABIs
//! ratchet_runtime_ffi::apply
//!   aos_apply context-decoding success-path wrapper for the frozen
//!   `(rt, Value, Value)` call ABI
//! ratchet_runtime_ffi::attr
//!   aos_has_attr, aos_select_ic, and aos_update success-path wrappers for
//!   frozen attrset-access ABIs
//! ratchet_runtime_ffi::barrier
//!   aos_gc_write_barrier trap-only wrapper for the frozen
//!   `(rt, thunk, Value)` write-barrier ABI
//! ratchet_runtime_ffi::wrappers
//!   unified process-local native-wrapper manifest in runtime-symbol order
//! ratchet_runtime_ffi::safety
//!   unsafe-boundary manifest and source-token allowlist
//! ```
//!
//! The wrappers here are not yet sufficient for final JIT registration. They
//! cover success-path ABI shape and process-local address metadata for focused
//! tests, while evaluator trap/error transfer remains an explicit blocker before
//! `aos-nix` can treat these symbols as complete native exports.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod alloc;
pub mod apply;
pub mod attr;
pub mod barrier;
pub mod env;
pub mod force;
pub mod safety;
pub mod wrappers;

pub use safety::{
    RUNTIME_FFI_SAFETY_COMMENT_PREFIX, RUNTIME_FFI_UNSAFE_CRATE_LINT,
    RuntimeFfiInnateUnsafeOperation, RuntimeFfiUnsafeDiscipline, runtime_ffi_unsafe_discipline,
};
