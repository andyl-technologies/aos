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
//! ratchet_runtime_ffi::context
//!   shared pinned runtime context decoded by mixed-helper native calls
//! ratchet_runtime_ffi::env
//!   aos_env_get success-path wrapper for the frozen `(env, slot) -> Value` ABI
//! ratchet_runtime_ffi::force
//!   aos_blackhole_check, aos_force, and aos_force_deep context-decoding
//!   success-path wrappers for frozen `(rt, Value)` forcing ABIs
//! ratchet_runtime_ffi::apply
//!   aos_apply context-decoding success-path wrapper for the frozen
//!   `(rt, Value, Value)` call ABI
//! ratchet_runtime_ffi::primop
//!   aos_primop_call context-decoding trampoline for the frozen
//!   `(rt, env, module_id, node_id)` primop-dispatch ABI
//! ratchet_runtime_ffi::attr
//!   aos_has_attr, aos_select_ic, and aos_update success-path wrappers for
//!   frozen attrset-access ABIs
//! ratchet_runtime_ffi::barrier
//!   aos_gc_write_barrier trap-only wrapper for the frozen
//!   `(rt, thunk, Value)` write-barrier ABI
//! ratchet_runtime_ffi::wrappers
//!   unified process-local native-wrapper manifest in runtime-symbol order
//! ratchet_runtime_ffi::trap
//!   scoped thread-local trap sink that transfers evaluator errors out of
//!   forcing and environment-access wrappers instead of aborting
//! ratchet_runtime_ffi::native_call
//!   safe orchestration of a registered native thunk call: pins the runtime
//!   context, installs a trap scope, and wraps the one unsafe jit call boundary
//! ratchet_runtime_ffi::safety
//!   unsafe-boundary manifest and source-token allowlist
//! ```
//!
//! The forcing and environment-access wrappers now transfer evaluator errors
//! through [`trap::RuntimeTrapScope`] instead of aborting, so a caller that
//! installs a scope can observe a failing evaluation. The allocation,
//! call-control, attrset-access, and write-barrier wrappers still cover only
//! success-path ABI shape and process-local address metadata; their evaluator
//! trap/error transfer remains an explicit blocker before `aos-nix` can treat
//! those symbols as complete native exports.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod alloc;
pub mod apply;
pub mod attr;
pub mod barrier;
pub mod context;
pub mod deopt;
pub mod env;
pub mod force;
pub mod native_call;
pub mod primop;
pub mod safety;
pub mod string_length;
pub mod stack_map;
pub mod trap;
pub mod wrappers;

pub use deopt::{RuntimeDeoptNativeFn, aos_deopt, aos_deopt_native_wrapper_address};
pub use env::{RuntimeUpvalGetNativeFn, aos_upval_get, aos_upval_get_native_wrapper_address};
pub use native_call::{
    NativeFilterLoopOutcome, NativeFoldLoopOutcome, NativeThunkCallOutcome,
    run_context_finalized_native_chain_call, run_context_finalized_native_filter_loop,
    run_context_finalized_native_fold_genlist_loop, run_context_finalized_native_fold_loop,
    run_context_finalized_native_lambda_call,
    run_context_finalized_native_thunk_call, run_finalized_native_thunk_call,
    run_registered_native_thunk_call,
};
pub use primop::{
    RuntimePrimopCallNativeFn, aos_primop_call, aos_primop_call_native_wrapper_address,
};
pub use string_length::{
    RuntimeStringLengthNativeFn, aos_string_length, aos_string_length_native_wrapper_address,
};
pub use stack_map::{
    RuntimeJitStackMapEnterNativeFn, RuntimeJitStackMapExitNativeFn,
    RuntimeJitStackMapWritebackError,
    aos_jit_stack_map_enter, aos_jit_stack_map_enter_native_wrapper_address,
    aos_jit_stack_map_exit, aos_jit_stack_map_exit_native_wrapper_address,
};
pub use safety::{
    RUNTIME_FFI_SAFETY_COMMENT_PREFIX, RUNTIME_FFI_UNSAFE_CRATE_LINT,
    RuntimeFfiInnateUnsafeOperation, RuntimeFfiUnsafeDiscipline, runtime_ffi_unsafe_discipline,
};
pub use trap::{RuntimeTrap, RuntimeTrapScope, runtime_trap_sentinel_value};
