//! Unsafe-discipline manifest for runtime FFI wrappers.
//!
//! `ratchet-runtime-ffi` is intentionally unsafe-capable because native runtime
//! helper wrappers must decode raw ABI pointers supplied by compiled code. This
//! module records the standing controls for that boundary and tests that current
//! source files keep every unsafe token on a reviewed allowlist.
/// Crate-level lint required for the runtime FFI unsafe boundary.
pub const RUNTIME_FFI_UNSAFE_CRATE_LINT: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

/// Comment prefix required beside each runtime FFI unsafe operation.
pub const RUNTIME_FFI_SAFETY_COMMENT_PREFIX: &str = "// SAFETY:";

/// The runtime FFI operation that remains innately unsafe after validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFfiInnateUnsafeOperation {
    /// Decodes a caller-supplied raw runtime pointer inside a native ABI wrapper.
    NativeWrapperPointerDecode,
}

/// Standing controls required before unsafe runtime FFI code can land.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFfiUnsafeDiscipline {
    crate_lint: &'static str,
    safety_comment_prefix: &'static str,
    second_reviewer_required: bool,
    sanitizer_ci_required: bool,
    innate_unsafe_operation: RuntimeFfiInnateUnsafeOperation,
}

impl RuntimeFfiUnsafeDiscipline {
    /// Creates the standing runtime FFI unsafe-discipline manifest.
    pub const fn new(
        crate_lint: &'static str,
        safety_comment_prefix: &'static str,
        second_reviewer_required: bool,
        sanitizer_ci_required: bool,
        innate_unsafe_operation: RuntimeFfiInnateUnsafeOperation,
    ) -> Self {
        Self {
            crate_lint,
            safety_comment_prefix,
            second_reviewer_required,
            sanitizer_ci_required,
            innate_unsafe_operation,
        }
    }

    /// Returns the crate-level lint required by the unsafe boundary.
    pub const fn crate_lint(self) -> &'static str {
        self.crate_lint
    }

    /// Returns the required local invariant-comment prefix.
    pub const fn safety_comment_prefix(self) -> &'static str {
        self.safety_comment_prefix
    }

    /// Returns whether a second reviewer is required for new unsafe blocks.
    pub const fn second_reviewer_required(self) -> bool {
        self.second_reviewer_required
    }

    /// Returns whether sanitizer CI must cover unsafe runtime FFI paths.
    pub const fn sanitizer_ci_required(self) -> bool {
        self.sanitizer_ci_required
    }

    /// Returns the innate unsafe operation isolated by this crate.
    pub const fn innate_unsafe_operation(self) -> RuntimeFfiInnateUnsafeOperation {
        self.innate_unsafe_operation
    }
}

/// Returns the standing unsafe-discipline manifest for `ratchet-runtime-ffi`.
pub const fn runtime_ffi_unsafe_discipline() -> RuntimeFfiUnsafeDiscipline {
    RuntimeFfiUnsafeDiscipline::new(
        RUNTIME_FFI_UNSAFE_CRATE_LINT,
        RUNTIME_FFI_SAFETY_COMMENT_PREFIX,
        true,
        true,
        RuntimeFfiInnateUnsafeOperation::NativeWrapperPointerDecode,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::*;

    mod stack_map;

    const UNSAFE_TOKEN: &str = concat!("uns", "afe");
    const EXTERN_TOKEN: &str = concat!("ext", "ern");
    const NO_MANGLE_TOKEN: &str = concat!("no_", "mangle");
    const ENV_GET_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeEnvGetNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, u32) -> Value;"
    );
    const ENV_GET_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const ENV_GET_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_env_get(env: *mut c_void, slot: u32) -> Value {"
    );
    const ENV_GET_DECODER_CALL_LINE: &str =
        concat!("uns", "afe { // aos_env_get runtime-environment decode");
    const DIRECT_TEST_CALL_LINE: &str =
        concat!("let actual = ", "uns", "afe { aos_env_get(env_ptr, 1) };");
    const BINDING_TEST_CALL_LINE: &str = concat!(
        "let actual = ",
        "uns",
        "afe { (binding.function())(env_ptr, 0) };"
    );
    const UPVAL_GET_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeUpvalGetNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, u32, u32) -> Value;"
    );
    const UPVAL_GET_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_upval_get(env: *mut c_void, depth: u32, slot: u32) -> Value {"
    );
    const UPVAL_GET_DECODER_CALL_LINE: &str =
        concat!("uns", "afe { // aos_upval_get runtime-environment decode");
    const UPVAL_INNERMOST_TEST_CALL_LINE: &str = concat!(
        "let innermost = ",
        "uns",
        "afe { aos_upval_get(env_ptr, 0, 0) };"
    );
    const UPVAL_PARENT_TEST_CALL_LINE: &str = concat!(
        "let parent = ",
        "uns",
        "afe { aos_upval_get(env_ptr, 1, 0) };"
    );
    const UPVAL_BAD_DEPTH_TEST_CALL_LINE: &str = concat!(
        "let value = ",
        "uns",
        "afe { aos_upval_get(env_ptr, 5, 0) };"
    );
    const DEOPT_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeDeoptNativeFn = ",
        "ext",
        "ern \"C\" fn(*mut c_void, *mut c_void) -> Value;"
    );
    const DEOPT_FN_LINE: &str = concat!(
        "pub ",
        "ext",
        "ern \"C\" fn aos_deopt(_rt: *mut c_void, _deopt_record: *mut c_void) -> Value {"
    );
    const RUNTIME_CONTEXT_DECODER_LINE: &str = concat!(
        "pub(crate) ",
        "uns",
        "afe fn with_native_runtime_context<R>("
    );
    const RUNTIME_ENV_CONTEXT_DECODER_LINE: &str = concat!(
        "pub(crate) ",
        "uns",
        "afe fn with_native_runtime_env_context<R>("
    );
    const RUNTIME_CONTEXT_CAST_LINE: &str = concat!(
        "let context = ",
        "uns",
        "afe { rt.cast::<RuntimeJitContext<'static>>().as_mut() };"
    );
    const RUNTIME_ENV_CONTEXT_CAST_LINE: &str = concat!(
        "let env_context = ",
        "uns",
        "afe { rt.cast::<RuntimeJitContext<'static>>().as_mut() };"
    );
    const RUNTIME_CONTEXT_EVAL_LINE: &str =
        concat!("call(", "uns", "afe { context.eval.as_mut() }, id, span)");
    const RUNTIME_ENV_CONTEXT_EVAL_LINE: &str =
        concat!("uns", "afe { env_context.eval.as_mut() },");
    const RUNTIME_ENV_CONTEXT_ENV_LINE: &str =
        concat!("uns", "afe { env.as_ref() },");
    const ALLOC_CODE_ENV_FN_TYPE_LINE: &str = concat!(
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;"
    );
    const ALLOC_ATTRS_FN_TYPE_LINE: &str = concat!(
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, u32, u32) -> *mut c_void;"
    );
    const ALLOC_CONS_FN_TYPE_LINE: &str = concat!(
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value, *mut c_void) -> *mut c_void;"
    );
    const ALLOC_LEN_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeAllocationLenNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, usize) -> *mut c_void;"
    );
    const ALLOC_RAW_FN_TYPE_LINE: &str = concat!(
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, usize, usize, u32) -> *mut c_void;"
    );
    const ALLOC_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const ALLOC_ATTRS_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_alloc_attrs("
    );
    const ALLOC_CONS_FN_LINE: &str = concat!("pub ", "uns", "afe ", "ext", "ern \"C\" fn aos_alloc_cons(");
    const ALLOC_CONS_DECODER_CALL_LINE: &str = concat!("let allocated = ", "uns", "afe { // aos_alloc_cons runtime-context decode");
    const ALLOC_LAMBDA_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_alloc_lambda("
    );
    const ALLOC_LIST_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_alloc_list(_rt: *mut c_void, _len: usize) -> *mut c_void {"
    );
    const ALLOC_RAW_FN_LINE: &str =
        concat!("pub ", "uns", "afe ", "ext", "ern \"C\" fn aos_alloc_raw(");
    const ALLOC_STRING_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_alloc_string(_rt: *mut c_void, _len: usize) -> *mut c_void {"
    );
    const ALLOC_THUNK_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_alloc_thunk("
    );
    const ALLOC_ATTRS_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_alloc_attrs(rt, shape, slots) };"
    );
    const ALLOC_CONS_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_alloc_cons(rt, head, tail) };");
    const ALLOC_LAMBDA_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_alloc_lambda(rt, code_ptr, env) };"
    );
    const ALLOC_LIST_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_alloc_list(rt, len) };");
    const ALLOC_RAW_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_alloc_raw(rt, size, align, type_tag) };"
    );
    const ALLOC_STRING_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_alloc_string(rt, len) };");
    const ALLOC_THUNK_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_alloc_thunk(rt, code_ptr, env) };"
    );
    const APPLY_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeApplyNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value, Value) -> Value;"
    );
    const APPLY_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const APPLY_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_apply(rt: *mut c_void, function: Value, argument: Value) -> Value {"
    );
    const APPLY_DECODER_CALL_LINE: &str = concat!("let applied = ", "uns", "afe {");
    const APPLY_DIRECT_LAMBDA_TEST_CALL_LINE: &str = concat!(
        "let actual = ",
        "uns",
        "afe { aos_apply(rt, function, Value::int(41)) };"
    );
    const APPLY_DIRECT_FUNCTOR_TEST_CALL_LINE: &str = concat!(
        "let functor_actual = ",
        "uns",
        "afe { aos_apply(rt, functor, Value::int(40)) };"
    );
    const APPLY_DIRECT_PRIMOP_PARTIAL_TEST_CALL_LINE: &str = concat!(
        "let partial = ",
        "uns",
        "afe { aos_apply(rt, function, Value::int(40)) };"
    );
    const APPLY_DIRECT_PRIMOP_RESULT_TEST_CALL_LINE: &str = concat!(
        "let primop_actual = ",
        "uns",
        "afe { aos_apply(rt, partial, Value::int(2)) };"
    );
    const APPLY_BINDING_TEST_CALL_LINE: &str = concat!(
        "let binding_actual = ",
        "uns",
        "afe { binding.function()(rt, function, Value::int(41)) };"
    );
    const APPLY_MALFORMED_VALUE_TRANSMUTE_LINE: &str = concat!(
        "uns",
        "afe { std::mem::transmute::<RawValueForTest, Value>(raw) }"
    );
    const APPLY_MALFORMED_FUNCTION_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_apply(rt, malformed, argument) };"
    );
    const APPLY_MALFORMED_ARGUMENT_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_apply(rt, function, malformed) };"
    );
    const APPLY_NULL_CONTEXT_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_apply(rt, function, argument) };"
    );
    const APPLY_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_apply(rt, function, Value::int(2)) };"
    );
    const ATTR_ACCESS_KEYED_FN_TYPE_LINE: &str = concat!(
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value, u32, u32) -> Value;"
    );
    const ATTR_UPDATE_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeAttrUpdateNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value, Value) -> Value;"
    );
    const ATTR_ACCESS_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const ATTR_HAS_ATTR_FN_LINE: &str =
        concat!("pub ", "uns", "afe ", "ext", "ern \"C\" fn aos_has_attr(");
    const ATTR_SELECT_IC_FN_LINE: &str =
        concat!("pub ", "uns", "afe ", "ext", "ern \"C\" fn aos_select_ic(");
    const ATTR_HAS_ATTR_DECODER_CALL_LINE: &str = concat!("let probed = ", "uns", "afe {");
    const ATTR_SELECT_IC_DECODER_CALL_LINE: &str = concat!("let selected = ", "uns", "afe {");
    const ATTR_UPDATE_DECODER_CALL_LINE: &str = concat!("let updated = ", "uns", "afe {");
    const ATTR_UPDATE_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_update(rt: *mut c_void, left: Value, right: Value) -> Value {"
    );
    const ATTR_HAS_ATTR_PRESENT_TEST_CALL_LINE: &str = concat!(
        "let present = ",
        "uns",
        "afe { aos_has_attr(rt, attrs, present_key.as_u32(), 7) };"
    );
    const ATTR_HAS_ATTR_REPEATED_TEST_CALL_LINE: &str = concat!(
        "let repeated_present = ",
        "uns",
        "afe { aos_has_attr(rt, attrs, present_key.as_u32(), 7) };"
    );
    const ATTR_HAS_ATTR_MISSING_TEST_CALL_LINE: &str = concat!(
        "let missing = ",
        "uns",
        "afe { aos_has_attr(rt, attrs, missing_key.as_u32(), 8) };"
    );
    const ATTR_HAS_ATTR_NON_ATTRS_TEST_CALL_LINE: &str = concat!(
        "let non_attrs = ",
        "uns",
        "afe { aos_has_attr(rt, Value::int(42), present_key.as_u32(), 9) };"
    );
    const ATTR_SELECT_IC_SELECTED_TEST_CALL_LINE: &str = concat!(
        "let selected = ",
        "uns",
        "afe { aos_select_ic(rt, attrs, key.as_u32(), 7) };"
    );
    const ATTR_SELECT_IC_REPEATED_TEST_CALL_LINE: &str = concat!(
        "let repeated = ",
        "uns",
        "afe { aos_select_ic(rt, attrs, key.as_u32(), 7) };"
    );
    const ATTR_UPDATE_SUCCESS_TEST_CALL_LINE: &str = concat!(
        "let result = ",
        "uns",
        "afe { aos_update(rt, left, right) };"
    );
    const ATTR_SELECT_IC_ERROR_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_select_ic(rt, attrs, missing_key.as_u32(), 7) };"
    );
    const ATTR_UPDATE_ERROR_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_update(rt, Value::int(42), attrs) };"
    );
    const ATTR_HAS_ATTR_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_has_attr(rt, attrs, symbol, site) };"
    );
    const ATTR_SELECT_IC_ABORT_TEST_CALL_LINE: &str = concat!(
        "let _ = ",
        "uns",
        "afe { aos_select_ic(rt, attrs, symbol, site) };"
    );
    const ATTR_UPDATE_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_update(rt, left, right) };");
    const WRITE_BARRIER_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeWriteBarrierNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, *mut c_void, Value);"
    );
    const WRITE_BARRIER_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const WRITE_BARRIER_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_gc_write_barrier("
    );
    const WRITE_BARRIER_ABORT_TEST_CALL_LINE: &str =
        concat!("uns", "afe { aos_gc_write_barrier(rt, thunk, value) };");
    const BLACKHOLE_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeBlackholeCheckNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value);"
    );
    const FORCE_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeForceNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value) -> Value;"
    );
    const FORCE_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const BLACKHOLE_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_blackhole_check(rt: *mut c_void, value: Value) {"
    );
    const FORCE_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_force(rt: *mut c_void, value: Value) -> Value {"
    );
    const FORCE_DEEP_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_force_deep(rt: *mut c_void, value: Value) -> Value {"
    );
    const BLACKHOLE_DECODER_CALL_LINE: &str = concat!("let checked = ", "uns", "afe {");
    const FORCE_DECODER_CALL_LINE: &str = concat!("let forced = ", "uns", "afe {");
    const FORCE_DEEP_DECODER_CALL_LINE: &str = concat!("let deeply_forced = ", "uns", "afe {");
    const DIRECT_BLACKHOLE_TEST_CALL_LINE: &str =
        concat!("uns", "afe { aos_blackhole_check(rt, value) };");
    const DIRECT_BLACKHOLE_THUNK_TEST_CALL_LINE: &str =
        concat!("uns", "afe { aos_blackhole_check(rt, thunk) };");
    const DIRECT_FORCE_TEST_CALL_LINE: &str =
        concat!("let actual = ", "uns", "afe { aos_force(rt, expected) };");
    const DIRECT_FORCE_THUNK_TEST_CALL_LINE: &str =
        concat!("let forced = ", "uns", "afe { aos_force(rt, thunk) };");
    const DIRECT_FORCE_DEEP_TEST_CALL_LINE: &str = concat!(
        "let actual = ",
        "uns",
        "afe { aos_force_deep(rt, expected) };"
    );
    const DIRECT_FORCE_DEEP_HEAP_TEST_CALL_LINE: &str = concat!(
        "let heap_actual = ",
        "uns",
        "afe { aos_force_deep(rt, heap_expected) };"
    );
    const DIRECT_FORCE_DEEP_NESTED_TEST_CALL_LINE: &str = concat!(
        "let deeply_forced = ",
        "uns",
        "afe { aos_force_deep(rt, root) };"
    );
    const DIRECT_FORCE_DEEP_ATTRSET_TEST_CALL_LINE: &str = concat!(
        "let attrset_deeply_forced = ",
        "uns",
        "afe { aos_force_deep(rt, root) };"
    );
    const FORCE_BINDING_TEST_CALL_LINE: &str =
        concat!("let actual = ", "uns", "afe { function(rt, expected) };");
    const FORCE_DEEP_BINDING_TEST_CALL_LINE: &str = concat!(
        "let deep_actual = ",
        "uns",
        "afe { function(rt, deep_expected) };"
    );
    const BLACKHOLE_BINDING_TEST_CALL_LINE: &str = concat!("uns", "afe { function(rt, value) };");
    const FORCE_MALFORMED_VALUE_TRANSMUTE_LINE: &str = concat!(
        "uns",
        "afe { std::mem::transmute::<RawValueForTest, Value>(raw) }"
    );
    const FORCE_MALFORMED_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force(rt, malformed) };");
    const FORCE_NULL_CONTEXT_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force(rt, value) };");
    const FORCE_THUNK_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force(rt, thunk) };");
    const FORCE_DEEP_MALFORMED_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force_deep(rt, malformed) };");
    const FORCE_DEEP_NULL_CONTEXT_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force_deep(rt, value) };");
    const FORCE_DEEP_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force_deep(rt, root) };");
    const BLACKHOLE_MALFORMED_ABORT_TEST_CALL_LINE: &str =
        concat!("uns", "afe { aos_blackhole_check(rt, malformed) };");
    const BLACKHOLE_NULL_CONTEXT_ABORT_TEST_CALL_LINE: &str =
        concat!("uns", "afe { aos_blackhole_check(rt, bool_value) };");
    const BLACKHOLE_BLACKHOLED_ABORT_TEST_CALL_LINE: &str =
        concat!("uns", "afe { aos_blackhole_check(rt, blackholed) };");
    const FINALIZED_CALL_JIT_BOUNDARY_LINE: &str = concat!(
        "let dispatched = ",
        "uns",
        "afe { jit_cranelift_call_finalized_thunk_entry(finalization, rt, env) };"
    );
    const CONTEXT_FINALIZED_CALL_JIT_BOUNDARY_LINE: &str = concat!(
        "let context_dispatched = ",
        "uns",
        "afe { jit_cranelift_call_context_finalized_thunk_entry(body, rt, env) };"
    );
    const CONTEXT_FINALIZED_LAMBDA_CALL_JIT_BOUNDARY_LINE: &str = concat!(
        "let lambda_dispatched = ",
        "uns",
        "afe { jit_cranelift_call_context_finalized_lambda_entry(body, rt, env, argument) };"
    );
    const CONTEXT_FINALIZED_CHAIN_CALL_JIT_BOUNDARY_LINE: &str = concat!(
        "let chain_call = ",
        "uns",
        "afe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, argv) };"
    );
    const CONTEXT_FINALIZED_FOLD_STEP_JIT_BOUNDARY_LINE: &str = concat!(
        "let fold_step = ",
        "uns",
        "afe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, &argv) };"
    );
    const CONTEXT_FINALIZED_FILTER_STEP_JIT_BOUNDARY_LINE: &str = concat!(
        "let filter_step = ",
        "uns",
        "afe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, &argv) };"
    );
    const CONTEXT_FINALIZED_ALL_ANY_STEP_JIT_BOUNDARY_LINE: &str = concat!(
        "let step = ",
        "uns",
        "afe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, &argv) };"
    );
    const PRIMOP_CALL_FN_TYPE_LINE: &str = concat!(
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, *mut c_void, u32, u32) -> Value;"
    );
    const PRIMOP_CALL_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const PRIMOP_CALL_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_primop_call("
    );
    const PRIMOP_CALL_DECODER_CALL_LINE: &str = concat!("uns", "afe {");
    const STRING_LENGTH_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeStringLengthNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value) -> Value;"
    );
    const STRING_LENGTH_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const STRING_LENGTH_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_string_length(rt: *mut c_void, value: Value) -> Value {"
    );
    const STRING_LENGTH_DECODER_CALL_LINE: &str = concat!("uns", "afe {");

    #[test]
    fn discipline_manifest_names_required_controls() {
        let discipline = runtime_ffi_unsafe_discipline();

        assert_eq!(discipline.crate_lint(), RUNTIME_FFI_UNSAFE_CRATE_LINT);
        assert_eq!(
            discipline.safety_comment_prefix(),
            RUNTIME_FFI_SAFETY_COMMENT_PREFIX
        );
        assert!(discipline.second_reviewer_required());
        assert!(discipline.sanitizer_ci_required());
        assert_eq!(
            discipline.innate_unsafe_operation(),
            RuntimeFfiInnateUnsafeOperation::NativeWrapperPointerDecode
        );
    }

    #[test]
    fn crate_root_declares_unsafe_operation_lint() {
        let crate_root = include_str!("lib.rs");
        let mut saw_item = false;

        for code in code_lines_without_comments_or_ordinary_strings(crate_root) {
            let trimmed = code.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == RUNTIME_FFI_UNSAFE_CRATE_LINT {
                assert!(
                    !saw_item,
                    "runtime FFI unsafe lint must appear before crate items"
                );
                return;
            }
            if trimmed.starts_with("pub ") {
                saw_item = true;
            }
        }

        panic!("crate root does not declare {RUNTIME_FFI_UNSAFE_CRATE_LINT}");
    }

    #[test]
    fn current_runtime_ffi_sources_keep_unsafe_boundaries_allowlisted() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut findings = Vec::new();

        assert_sources_compile_only_from_scanned_tree(&source_root);

        for source_path in rust_sources(&source_root) {
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            let raw_lines = source.lines().collect::<Vec<_>>();
            let code_lines = code_lines_without_comments_or_ordinary_strings(&source);
            assert_eq!(
                raw_lines.len(),
                code_lines.len(),
                "source filter must preserve line count for {}",
                source_path.display()
            );

            for (line_number, code) in code_lines.iter().enumerate() {
                let line = raw_lines[line_number];
                for token in code_tokens(code) {
                    if is_allowed_env_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_runtime_context_token(&source_root, &source_path, line, token)
                        || is_allowed_alloc_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_apply_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_attr_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_write_barrier_wrapper_token(
                            &source_root,
                            &source_path,
                            line,
                            token,
                        )
                        || is_allowed_force_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_native_call_token(&source_root, &source_path, line, token)
                        || is_allowed_deopt_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_primop_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_string_length_wrapper_token(
                            &source_root,
                            &source_path,
                            line,
                            token,
                        )
                        || stack_map::is_allowed_token(
                            &source_root,
                            &source_path,
                            line,
                            token,
                        )
                    {
                        continue;
                    }

                    if is_unsafe_boundary_token(token) {
                        findings.push(format!(
                            "{}:{} contains `{token}`",
                            source_path.display(),
                            line_number + 1
                        ));
                    }
                }
            }
        }

        assert!(
            findings.is_empty(),
            "ratchet-runtime-ffi contains unreviewed unsafe-boundary tokens:\n{}",
            findings.join("\n")
        );

        assert_reviewed_unsafe_boundary_counts(&source_root);
        assert_reviewed_safety_comments(&source_root);
        assert_public_unsafe_docs(&source_root);
        stack_map::assert_reviewed(&source_root);
    }

    fn is_allowed_env_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("env.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == ENV_GET_FN_TYPE_LINE
                || trimmed == ENV_GET_EXPORT_ATTR_LINE
                || trimmed == ENV_GET_FN_LINE
                || trimmed == ENV_GET_DECODER_CALL_LINE
                || trimmed == DIRECT_TEST_CALL_LINE
                || trimmed == BINDING_TEST_CALL_LINE
                || trimmed == UPVAL_GET_FN_TYPE_LINE
                || trimmed == UPVAL_GET_FN_LINE
                || trimmed == UPVAL_GET_DECODER_CALL_LINE
                || trimmed == UPVAL_INNERMOST_TEST_CALL_LINE
                || trimmed == UPVAL_PARENT_TEST_CALL_LINE
                || trimmed == UPVAL_BAD_DEPTH_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == ENV_GET_FN_TYPE_LINE
                || trimmed == ENV_GET_FN_LINE
                || trimmed == UPVAL_GET_FN_TYPE_LINE
                || trimmed == UPVAL_GET_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == ENV_GET_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_alloc_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("alloc.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == ALLOC_CODE_ENV_FN_TYPE_LINE
                || trimmed == ALLOC_ATTRS_FN_TYPE_LINE
                || trimmed == ALLOC_CONS_FN_TYPE_LINE
                || trimmed == ALLOC_LEN_FN_TYPE_LINE
                || trimmed == ALLOC_RAW_FN_TYPE_LINE
                || trimmed == ALLOC_EXPORT_ATTR_LINE
                || trimmed == ALLOC_ATTRS_FN_LINE
                || trimmed == ALLOC_CONS_FN_LINE || trimmed == ALLOC_CONS_DECODER_CALL_LINE
                || trimmed == ALLOC_LAMBDA_FN_LINE
                || trimmed == ALLOC_LIST_FN_LINE
                || trimmed == ALLOC_RAW_FN_LINE
                || trimmed == ALLOC_STRING_FN_LINE
                || trimmed == ALLOC_THUNK_FN_LINE
                || trimmed == ALLOC_ATTRS_ABORT_TEST_CALL_LINE
                || trimmed == ALLOC_CONS_ABORT_TEST_CALL_LINE
                || trimmed == ALLOC_LAMBDA_ABORT_TEST_CALL_LINE
                || trimmed == ALLOC_LIST_ABORT_TEST_CALL_LINE
                || trimmed == ALLOC_RAW_ABORT_TEST_CALL_LINE
                || trimmed == ALLOC_STRING_ABORT_TEST_CALL_LINE
                || trimmed == ALLOC_THUNK_ABORT_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == ALLOC_CODE_ENV_FN_TYPE_LINE
                || trimmed == ALLOC_ATTRS_FN_TYPE_LINE
                || trimmed == ALLOC_CONS_FN_TYPE_LINE
                || trimmed == ALLOC_LEN_FN_TYPE_LINE
                || trimmed == ALLOC_RAW_FN_TYPE_LINE
                || trimmed == ALLOC_ATTRS_FN_LINE
                || trimmed == ALLOC_CONS_FN_LINE
                || trimmed == ALLOC_LAMBDA_FN_LINE
                || trimmed == ALLOC_LIST_FN_LINE
                || trimmed == ALLOC_RAW_FN_LINE
                || trimmed == ALLOC_STRING_FN_LINE
                || trimmed == ALLOC_THUNK_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == ALLOC_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_runtime_context_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("context.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == RUNTIME_CONTEXT_DECODER_LINE
                || trimmed == RUNTIME_ENV_CONTEXT_DECODER_LINE
                || trimmed == RUNTIME_CONTEXT_CAST_LINE
                || trimmed == RUNTIME_ENV_CONTEXT_CAST_LINE
                || trimmed == RUNTIME_CONTEXT_EVAL_LINE
                || trimmed == RUNTIME_ENV_CONTEXT_EVAL_LINE
                || trimmed == RUNTIME_ENV_CONTEXT_ENV_LINE
        } else {
            false
        }
    }

    fn is_allowed_primop_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("primop.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == PRIMOP_CALL_FN_TYPE_LINE
                || trimmed == PRIMOP_CALL_EXPORT_ATTR_LINE
                || trimmed == PRIMOP_CALL_FN_LINE
                || trimmed == PRIMOP_CALL_DECODER_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == PRIMOP_CALL_FN_TYPE_LINE || trimmed == PRIMOP_CALL_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == PRIMOP_CALL_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_string_length_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("string_length.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == STRING_LENGTH_FN_TYPE_LINE
                || trimmed == STRING_LENGTH_EXPORT_ATTR_LINE
                || trimmed == STRING_LENGTH_FN_LINE
                || trimmed == STRING_LENGTH_DECODER_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == STRING_LENGTH_FN_TYPE_LINE || trimmed == STRING_LENGTH_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == STRING_LENGTH_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_apply_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("apply.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == APPLY_FN_TYPE_LINE
                || trimmed == APPLY_EXPORT_ATTR_LINE
                || trimmed == APPLY_FN_LINE
                || trimmed == APPLY_DECODER_CALL_LINE
                || trimmed == APPLY_DIRECT_LAMBDA_TEST_CALL_LINE
                || trimmed == APPLY_DIRECT_FUNCTOR_TEST_CALL_LINE
                || trimmed == APPLY_DIRECT_PRIMOP_PARTIAL_TEST_CALL_LINE
                || trimmed == APPLY_DIRECT_PRIMOP_RESULT_TEST_CALL_LINE
                || trimmed == APPLY_BINDING_TEST_CALL_LINE
                || trimmed == APPLY_MALFORMED_VALUE_TRANSMUTE_LINE
                || trimmed == APPLY_MALFORMED_FUNCTION_ABORT_TEST_CALL_LINE
                || trimmed == APPLY_MALFORMED_ARGUMENT_ABORT_TEST_CALL_LINE
                || trimmed == APPLY_NULL_CONTEXT_ABORT_TEST_CALL_LINE
                || trimmed == APPLY_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == APPLY_FN_TYPE_LINE || trimmed == APPLY_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == APPLY_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_force_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("force.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == BLACKHOLE_FN_TYPE_LINE
                || trimmed == FORCE_FN_TYPE_LINE
                || trimmed == FORCE_EXPORT_ATTR_LINE
                || trimmed == BLACKHOLE_FN_LINE
                || trimmed == FORCE_FN_LINE
                || trimmed == FORCE_DEEP_FN_LINE
                || trimmed == BLACKHOLE_DECODER_CALL_LINE
                || trimmed == FORCE_DECODER_CALL_LINE
                || trimmed == FORCE_DEEP_DECODER_CALL_LINE
                || trimmed == DIRECT_BLACKHOLE_TEST_CALL_LINE
                || trimmed == DIRECT_BLACKHOLE_THUNK_TEST_CALL_LINE
                || trimmed == DIRECT_FORCE_TEST_CALL_LINE
                || trimmed == DIRECT_FORCE_THUNK_TEST_CALL_LINE
                || trimmed == DIRECT_FORCE_DEEP_TEST_CALL_LINE
                || trimmed == DIRECT_FORCE_DEEP_HEAP_TEST_CALL_LINE
                || trimmed == DIRECT_FORCE_DEEP_NESTED_TEST_CALL_LINE
                || trimmed == DIRECT_FORCE_DEEP_ATTRSET_TEST_CALL_LINE
                || trimmed == FORCE_BINDING_TEST_CALL_LINE
                || trimmed == FORCE_DEEP_BINDING_TEST_CALL_LINE
                || trimmed == BLACKHOLE_BINDING_TEST_CALL_LINE
                || trimmed == FORCE_MALFORMED_VALUE_TRANSMUTE_LINE
                || trimmed == FORCE_MALFORMED_ABORT_TEST_CALL_LINE
                || trimmed == FORCE_NULL_CONTEXT_ABORT_TEST_CALL_LINE
                || trimmed == FORCE_THUNK_ABORT_TEST_CALL_LINE
                || trimmed == FORCE_DEEP_MALFORMED_ABORT_TEST_CALL_LINE
                || trimmed == FORCE_DEEP_NULL_CONTEXT_ABORT_TEST_CALL_LINE
                || trimmed == FORCE_DEEP_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE
                || trimmed == BLACKHOLE_MALFORMED_ABORT_TEST_CALL_LINE
                || trimmed == BLACKHOLE_NULL_CONTEXT_ABORT_TEST_CALL_LINE
                || trimmed == BLACKHOLE_BLACKHOLED_ABORT_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == BLACKHOLE_FN_TYPE_LINE
                || trimmed == FORCE_FN_TYPE_LINE
                || trimmed == BLACKHOLE_FN_LINE
                || trimmed == FORCE_FN_LINE
                || trimmed == FORCE_DEEP_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == FORCE_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_native_call_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("native_call.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == FINALIZED_CALL_JIT_BOUNDARY_LINE
                || trimmed == CONTEXT_FINALIZED_CALL_JIT_BOUNDARY_LINE
                || trimmed == CONTEXT_FINALIZED_LAMBDA_CALL_JIT_BOUNDARY_LINE
                || trimmed == CONTEXT_FINALIZED_CHAIN_CALL_JIT_BOUNDARY_LINE
                || trimmed == CONTEXT_FINALIZED_FOLD_STEP_JIT_BOUNDARY_LINE
                || trimmed == CONTEXT_FINALIZED_FILTER_STEP_JIT_BOUNDARY_LINE
                || trimmed == CONTEXT_FINALIZED_ALL_ANY_STEP_JIT_BOUNDARY_LINE
        } else {
            false
        }
    }

    /// The deopt wrapper carries only `extern "C"` boundary tokens: it decodes no
    /// pointers, so its body has no `unsafe` and it is not `#[no_mangle]`.
    fn is_allowed_deopt_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("deopt.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == EXTERN_TOKEN {
            trimmed == DEOPT_FN_TYPE_LINE || trimmed == DEOPT_FN_LINE
        } else {
            false
        }
    }

    fn is_allowed_attr_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("attr.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == ATTR_ACCESS_KEYED_FN_TYPE_LINE
                || trimmed == ATTR_UPDATE_FN_TYPE_LINE
                || trimmed == ATTR_ACCESS_EXPORT_ATTR_LINE
                || trimmed == ATTR_HAS_ATTR_FN_LINE
                || trimmed == ATTR_SELECT_IC_FN_LINE
                || trimmed == ATTR_HAS_ATTR_DECODER_CALL_LINE
                || trimmed == ATTR_SELECT_IC_DECODER_CALL_LINE
                || trimmed == ATTR_UPDATE_DECODER_CALL_LINE
                || trimmed == ATTR_UPDATE_FN_LINE
                || trimmed == ATTR_HAS_ATTR_PRESENT_TEST_CALL_LINE
                || trimmed == ATTR_HAS_ATTR_REPEATED_TEST_CALL_LINE
                || trimmed == ATTR_HAS_ATTR_MISSING_TEST_CALL_LINE
                || trimmed == ATTR_HAS_ATTR_NON_ATTRS_TEST_CALL_LINE
                || trimmed == ATTR_SELECT_IC_SELECTED_TEST_CALL_LINE
                || trimmed == ATTR_SELECT_IC_REPEATED_TEST_CALL_LINE
                || trimmed == ATTR_UPDATE_SUCCESS_TEST_CALL_LINE
                || trimmed == ATTR_SELECT_IC_ERROR_TEST_CALL_LINE
                || trimmed == ATTR_UPDATE_ERROR_TEST_CALL_LINE
                || trimmed == ATTR_HAS_ATTR_ABORT_TEST_CALL_LINE
                || trimmed == ATTR_SELECT_IC_ABORT_TEST_CALL_LINE
                || trimmed == ATTR_UPDATE_ABORT_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == ATTR_ACCESS_KEYED_FN_TYPE_LINE
                || trimmed == ATTR_UPDATE_FN_TYPE_LINE
                || trimmed == ATTR_HAS_ATTR_FN_LINE
                || trimmed == ATTR_SELECT_IC_FN_LINE
                || trimmed == ATTR_UPDATE_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == ATTR_ACCESS_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_write_barrier_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("barrier.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == WRITE_BARRIER_FN_TYPE_LINE
                || trimmed == WRITE_BARRIER_EXPORT_ATTR_LINE
                || trimmed == WRITE_BARRIER_FN_LINE
                || trimmed == WRITE_BARRIER_ABORT_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == WRITE_BARRIER_FN_TYPE_LINE || trimmed == WRITE_BARRIER_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == WRITE_BARRIER_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_unsafe_boundary_token(token: &str) -> bool {
        [UNSAFE_TOKEN, EXTERN_TOKEN, NO_MANGLE_TOKEN].contains(&token)
    }

    #[test]
    fn source_retargeting_detection_rejects_unscanned_rust_inputs() {
        let findings = source_retargeting_findings(
            Path::new("synthetic.rs"),
            r#"
include!("../unchecked.rs");
#[path = "../unchecked.rs"]
mod unchecked;
#[cfg_attr(feature = "ffi", path = "../unchecked_cfg.rs")]
mod unchecked_cfg;
"#,
        );

        assert_eq!(findings.len(), 3);
        assert!(
            findings
                .iter()
                .any(|finding| finding.contains(INCLUDE_MACRO_LABEL))
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.contains(PATH_ATTRIBUTE_LABEL))
                .count(),
            2
        );
    }

    fn rust_sources(root: &Path) -> Vec<PathBuf> {
        let mut sources = Vec::new();
        collect_rust_sources(root, &mut sources);
        sources.sort();
        sources
    }

    fn collect_rust_sources(path: &Path, sources: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("source directory is readable") {
                collect_rust_sources(&entry.expect("source entry is readable").path(), sources);
            }
            return;
        }

        if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path.to_path_buf());
        }
    }

    fn code_lines_without_comments_or_ordinary_strings(source: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let mut in_string = false;
        let mut raw_string_hashes = None;
        let mut escaped = false;
        let mut block_comment_depth = 0usize;

        for line in source.lines() {
            let mut code = String::with_capacity(line.len());
            let chars = line.chars().collect::<Vec<_>>();
            let mut index = 0;

            while index < chars.len() {
                if let Some(hashes) = raw_string_hashes {
                    if chars[index] == '"' && raw_string_terminator_matches(&chars, index, hashes) {
                        for _ in 0..=hashes {
                            code.push(' ');
                        }
                        index += hashes + 1;
                        raw_string_hashes = None;
                    } else {
                        code.push(' ');
                        index += 1;
                    }
                    continue;
                }

                let ch = chars[index];
                if block_comment_depth > 0 {
                    if ch == '/' && chars.get(index + 1) == Some(&'*') {
                        block_comment_depth += 1;
                        code.push(' ');
                        code.push(' ');
                        index += 2;
                    } else if ch == '*' && chars.get(index + 1) == Some(&'/') {
                        block_comment_depth -= 1;
                        code.push(' ');
                        code.push(' ');
                        index += 2;
                    } else {
                        code.push(' ');
                        index += 1;
                    }
                    continue;
                }

                if !in_string && ch == '/' && chars.get(index + 1) == Some(&'/') {
                    break;
                }

                if !in_string && ch == '/' && chars.get(index + 1) == Some(&'*') {
                    block_comment_depth += 1;
                    code.push(' ');
                    code.push(' ');
                    index += 2;
                    continue;
                }

                if !in_string && let Some((delimiter_len, hashes)) = raw_string_start(&chars, index)
                {
                    for _ in 0..delimiter_len {
                        code.push(' ');
                    }
                    index += delimiter_len;
                    raw_string_hashes = Some(hashes);
                    continue;
                }

                if ch == '"' && !escaped {
                    in_string = !in_string;
                    code.push(' ');
                } else if in_string {
                    code.push(' ');
                } else {
                    code.push(ch);
                }

                escaped = ch == '\\' && !escaped;
                if ch != '\\' {
                    escaped = false;
                }

                index += 1;
            }

            lines.push(code);
        }

        lines
    }

    fn raw_string_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
        let raw_prefix_index = if chars.get(index) == Some(&'r') {
            index
        } else if chars.get(index) == Some(&'b') && chars.get(index + 1) == Some(&'r') {
            index + 1
        } else {
            return None;
        };

        let mut cursor = raw_prefix_index + 1;
        while chars.get(cursor) == Some(&'#') {
            cursor += 1;
        }

        if chars.get(cursor) == Some(&'"') {
            Some((cursor - index + 1, cursor - raw_prefix_index - 1))
        } else {
            None
        }
    }

    fn raw_string_terminator_matches(chars: &[char], quote_index: usize, hashes: usize) -> bool {
        (0..hashes).all(|offset| chars.get(quote_index + 1 + offset) == Some(&'#'))
    }

    fn code_tokens(code: &str) -> impl Iterator<Item = &str> {
        code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|token| !token.is_empty())
    }

    fn assert_sources_compile_only_from_scanned_tree(source_root: &Path) {
        let mut findings = Vec::new();

        for source_path in rust_sources(source_root) {
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            findings.extend(source_retargeting_findings(&source_path, &source));
        }

        assert!(
            findings.is_empty(),
            "ratchet-runtime-ffi may not retarget compiled Rust outside scanned src files:\n{}",
            findings.join("\n")
        );
    }

    fn source_retargeting_findings(source_path: &Path, source: &str) -> Vec<String> {
        let mut findings = Vec::new();
        let mut inside_attribute = false;

        for (line_number, code) in code_lines_without_comments_or_ordinary_strings(source)
            .iter()
            .enumerate()
        {
            let tokens = code_tokens(code).collect::<Vec<_>>();
            let trimmed = code.trim_start();
            if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                inside_attribute = true;
            }

            if tokens.contains(&INCLUDE_TOKEN) {
                findings.push(format!(
                    "{}:{} contains `{INCLUDE_MACRO_LABEL}`",
                    source_path.display(),
                    line_number + 1
                ));
            }

            if inside_attribute && tokens.contains(&PATH_TOKEN) {
                findings.push(format!(
                    "{}:{} contains `{PATH_ATTRIBUTE_LABEL}`",
                    source_path.display(),
                    line_number + 1
                ));
            }

            if inside_attribute && code.contains(']') {
                inside_attribute = false;
            }
        }

        findings
    }

    const INCLUDE_TOKEN: &str = concat!("incl", "ude");
    const INCLUDE_MACRO_LABEL: &str = concat!("incl", "ude!");
    const PATH_TOKEN: &str = concat!("pa", "th");
    const PATH_ATTRIBUTE_LABEL: &str = concat!("#[", "pa", "th]");

    fn assert_reviewed_unsafe_boundary_counts(source_root: &Path) {
        let alloc = fs::read_to_string(source_root.join("alloc.rs"))
            .expect("allocation FFI source file is readable");
        let apply = fs::read_to_string(source_root.join("apply.rs"))
            .expect("apply FFI source file is readable");
        let attr = fs::read_to_string(source_root.join("attr.rs"))
            .expect("attrset-access FFI source file is readable");
        let env = fs::read_to_string(source_root.join("env.rs"))
            .expect("environment FFI source file is readable");
        let context = fs::read_to_string(source_root.join("context.rs"))
            .expect("shared runtime context FFI source file is readable");
        let barrier = fs::read_to_string(source_root.join("barrier.rs"))
            .expect("write-barrier FFI source file is readable");
        let force =
            fs::read_to_string(source_root.join("force.rs")).expect("force FFI source is readable");
        let native_call = fs::read_to_string(source_root.join("native_call.rs"))
            .expect("native-call FFI source file is readable");

        for (line, boundary) in [
            (FINALIZED_CALL_JIT_BOUNDARY_LINE, "thunk call"),
            (CONTEXT_FINALIZED_CALL_JIT_BOUNDARY_LINE, "context thunk call"),
            (CONTEXT_FINALIZED_LAMBDA_CALL_JIT_BOUNDARY_LINE, "lambda call"),
            (CONTEXT_FINALIZED_CHAIN_CALL_JIT_BOUNDARY_LINE, "chain call"),
            (CONTEXT_FINALIZED_FOLD_STEP_JIT_BOUNDARY_LINE, "fold step"),
            (CONTEXT_FINALIZED_FILTER_STEP_JIT_BOUNDARY_LINE, "filter step"),
            (CONTEXT_FINALIZED_ALL_ANY_STEP_JIT_BOUNDARY_LINE, "all/any step"),
        ] {
            assert_eq!(
                trimmed_line_occurrences(&native_call, line),
                1,
                "shared-context finalized native {boundary} boundary must stay singly reviewed"
            );
        }
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_FN_TYPE_LINE),
            1,
            "env native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_EXPORT_ATTR_LINE),
            2,
            "the aos_env_get and aos_upval_get export attributes must stay reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_FN_LINE),
            1,
            "aos_env_get native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_DECODER_CALL_LINE),
            1,
            "aos_env_get wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, UPVAL_GET_DECODER_CALL_LINE),
            1,
            "aos_upval_get wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, DIRECT_TEST_CALL_LINE),
            1,
            "direct test call of aos_env_get must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, BINDING_TEST_CALL_LINE),
            1,
            "metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_CONTEXT_DECODER_LINE),
            1,
            "raw shared runtime context decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_ENV_CONTEXT_DECODER_LINE),
            1,
            "raw shared runtime environment decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_CONTEXT_CAST_LINE),
            1,
            "raw shared runtime context cast must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_ENV_CONTEXT_CAST_LINE),
            1,
            "raw shared runtime environment context cast must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_CONTEXT_EVAL_LINE),
            1,
            "raw shared runtime TreeWalk pointer cast must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_ENV_CONTEXT_EVAL_LINE),
            1,
            "raw shared runtime evaluator pointer must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&context, RUNTIME_ENV_CONTEXT_ENV_LINE),
            1,
            "raw shared runtime environment pointer must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_CODE_ENV_FN_TYPE_LINE),
            1,
            "allocation code/env native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_ATTRS_FN_TYPE_LINE),
            1,
            "allocation attrset native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_CONS_FN_TYPE_LINE),
            1,
            "allocation cons native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_LEN_FN_TYPE_LINE),
            1,
            "allocation length native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_RAW_FN_TYPE_LINE),
            1,
            "allocation raw native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_EXPORT_ATTR_LINE),
            7,
            "allocation native wrapper export attributes must stay reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_ATTRS_FN_LINE),
            1,
            "aos_alloc_attrs native wrapper must stay singly reviewed"
        );
        assert_eq!(
            (trimmed_line_occurrences(&alloc, ALLOC_CONS_FN_LINE), trimmed_line_occurrences(&alloc, ALLOC_CONS_DECODER_CALL_LINE)),
            (1, 1),
            "aos_alloc_cons wrapper and runtime decode must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_LAMBDA_FN_LINE),
            1,
            "aos_alloc_lambda native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_LIST_FN_LINE),
            1,
            "aos_alloc_list native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_RAW_FN_LINE),
            1,
            "aos_alloc_raw native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_STRING_FN_LINE),
            1,
            "aos_alloc_string native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_THUNK_FN_LINE),
            1,
            "aos_alloc_thunk native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_ATTRS_ABORT_TEST_CALL_LINE),
            1,
            "attrset allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_CONS_ABORT_TEST_CALL_LINE),
            1,
            "cons allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_LAMBDA_ABORT_TEST_CALL_LINE),
            1,
            "lambda allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_LIST_ABORT_TEST_CALL_LINE),
            1,
            "list allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_RAW_ABORT_TEST_CALL_LINE),
            1,
            "raw allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_STRING_ABORT_TEST_CALL_LINE),
            1,
            "string allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&alloc, ALLOC_THUNK_ABORT_TEST_CALL_LINE),
            1,
            "thunk allocation abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_FN_TYPE_LINE),
            1,
            "apply native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_EXPORT_ATTR_LINE),
            1,
            "apply native wrapper export attribute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_FN_LINE),
            1,
            "aos_apply native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_DECODER_CALL_LINE),
            1,
            "aos_apply wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_DIRECT_LAMBDA_TEST_CALL_LINE),
            1,
            "direct lambda test call of aos_apply must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_DIRECT_FUNCTOR_TEST_CALL_LINE),
            1,
            "direct functor test call of aos_apply must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_DIRECT_PRIMOP_PARTIAL_TEST_CALL_LINE),
            1,
            "direct primop partial test call of aos_apply must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_DIRECT_PRIMOP_RESULT_TEST_CALL_LINE),
            1,
            "direct primop result test call of aos_apply must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_BINDING_TEST_CALL_LINE),
            1,
            "apply metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_MALFORMED_VALUE_TRANSMUTE_LINE),
            1,
            "apply malformed Value construction test must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_MALFORMED_FUNCTION_ABORT_TEST_CALL_LINE),
            1,
            "apply malformed function abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_MALFORMED_ARGUMENT_ABORT_TEST_CALL_LINE),
            1,
            "apply malformed argument abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_NULL_CONTEXT_ABORT_TEST_CALL_LINE),
            1,
            "apply null-context abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&apply, APPLY_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE),
            1,
            "apply tree-walk error abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_ACCESS_KEYED_FN_TYPE_LINE),
            1,
            "keyed attrset-access native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_UPDATE_FN_TYPE_LINE),
            1,
            "attrset-update native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_ACCESS_EXPORT_ATTR_LINE),
            3,
            "attrset-access native wrapper export attributes must stay reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_FN_LINE),
            1,
            "aos_has_attr native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_SELECT_IC_FN_LINE),
            1,
            "aos_select_ic native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_DECODER_CALL_LINE),
            1,
            "aos_has_attr wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_SELECT_IC_DECODER_CALL_LINE),
            1,
            "aos_select_ic wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_UPDATE_DECODER_CALL_LINE),
            1,
            "aos_update wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_UPDATE_FN_LINE),
            1,
            "aos_update native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_PRESENT_TEST_CALL_LINE),
            1,
            "direct has-attr presence test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_REPEATED_TEST_CALL_LINE),
            1,
            "direct has-attr repeated test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_MISSING_TEST_CALL_LINE),
            1,
            "direct has-attr missing test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_NON_ATTRS_TEST_CALL_LINE),
            1,
            "direct has-attr non-attrs test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_SELECT_IC_SELECTED_TEST_CALL_LINE),
            1,
            "direct select-IC selected test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_SELECT_IC_REPEATED_TEST_CALL_LINE),
            1,
            "direct select-IC repeated test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_UPDATE_SUCCESS_TEST_CALL_LINE),
            1,
            "direct attrset-update success test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_SELECT_IC_ERROR_TEST_CALL_LINE),
            1,
            "select-IC tree-walk error abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_UPDATE_ERROR_TEST_CALL_LINE),
            1,
            "attrset-update tree-walk error abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_HAS_ATTR_ABORT_TEST_CALL_LINE),
            1,
            "has-attr abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_SELECT_IC_ABORT_TEST_CALL_LINE),
            1,
            "select-IC abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&attr, ATTR_UPDATE_ABORT_TEST_CALL_LINE),
            1,
            "attrset-update abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&barrier, WRITE_BARRIER_FN_TYPE_LINE),
            1,
            "write-barrier native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&barrier, WRITE_BARRIER_EXPORT_ATTR_LINE),
            1,
            "write-barrier native wrapper export attribute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&barrier, WRITE_BARRIER_FN_LINE),
            1,
            "aos_gc_write_barrier native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&barrier, WRITE_BARRIER_ABORT_TEST_CALL_LINE),
            1,
            "write-barrier abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_FN_TYPE_LINE),
            1,
            "blackhole-check native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_FN_TYPE_LINE),
            1,
            "force native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_EXPORT_ATTR_LINE),
            3,
            "force native wrapper export attributes must stay reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_FN_LINE),
            1,
            "aos_blackhole_check native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_FN_LINE),
            1,
            "aos_force native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DEEP_FN_LINE),
            1,
            "aos_force_deep native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_DECODER_CALL_LINE),
            1,
            "aos_blackhole_check wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DECODER_CALL_LINE),
            1,
            "aos_force wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DEEP_DECODER_CALL_LINE),
            1,
            "aos_force_deep wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_BLACKHOLE_TEST_CALL_LINE),
            1,
            "direct test call of aos_blackhole_check must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_BLACKHOLE_THUNK_TEST_CALL_LINE),
            1,
            "direct thunk test call of aos_blackhole_check must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_TEST_CALL_LINE),
            1,
            "direct test call of aos_force must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_THUNK_TEST_CALL_LINE),
            1,
            "direct thunk test call of aos_force must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_DEEP_TEST_CALL_LINE),
            1,
            "direct test call of aos_force_deep must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_DEEP_HEAP_TEST_CALL_LINE),
            1,
            "direct heap-leaf test call of aos_force_deep must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_DEEP_NESTED_TEST_CALL_LINE),
            1,
            "direct nested-container test call of aos_force_deep must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_DEEP_ATTRSET_TEST_CALL_LINE),
            1,
            "direct nested-attrset test call of aos_force_deep must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_BINDING_TEST_CALL_LINE),
            1,
            "force metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DEEP_BINDING_TEST_CALL_LINE),
            1,
            "force-deep metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_BINDING_TEST_CALL_LINE),
            1,
            "blackhole metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_MALFORMED_VALUE_TRANSMUTE_LINE),
            1,
            "malformed Value construction test must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_MALFORMED_ABORT_TEST_CALL_LINE),
            1,
            "malformed payload abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_NULL_CONTEXT_ABORT_TEST_CALL_LINE),
            1,
            "force null-context abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_THUNK_ABORT_TEST_CALL_LINE),
            1,
            "force tree-walk error abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DEEP_MALFORMED_ABORT_TEST_CALL_LINE),
            1,
            "force-deep malformed payload abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DEEP_NULL_CONTEXT_ABORT_TEST_CALL_LINE),
            1,
            "force-deep null-context abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_DEEP_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE),
            1,
            "force-deep tree-walk error abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_MALFORMED_ABORT_TEST_CALL_LINE),
            1,
            "blackhole malformed payload abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_NULL_CONTEXT_ABORT_TEST_CALL_LINE),
            1,
            "blackhole null-context abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, BLACKHOLE_BLACKHOLED_ABORT_TEST_CALL_LINE),
            1,
            "blackhole blackholed-thunk abort test call must stay singly reviewed"
        );
    }

    fn assert_reviewed_safety_comments(source_root: &Path) {
        let alloc = fs::read_to_string(source_root.join("alloc.rs"))
            .expect("allocation FFI source file is readable");
        let apply = fs::read_to_string(source_root.join("apply.rs"))
            .expect("apply FFI source file is readable");
        let attr = fs::read_to_string(source_root.join("attr.rs"))
            .expect("attrset-access FFI source file is readable");
        let env = fs::read_to_string(source_root.join("env.rs"))
            .expect("environment FFI source file is readable");
        let context = fs::read_to_string(source_root.join("context.rs"))
            .expect("shared runtime context FFI source file is readable");
        let barrier = fs::read_to_string(source_root.join("barrier.rs"))
            .expect("write-barrier FFI source file is readable");
        let force =
            fs::read_to_string(source_root.join("force.rs")).expect("force FFI source is readable");
        let native_call = fs::read_to_string(source_root.join("native_call.rs"))
            .expect("native-call FFI source file is readable");
        let apply_lines = apply.lines().collect::<Vec<_>>();
        let alloc_lines = alloc.lines().collect::<Vec<_>>();
        let attr_lines = attr.lines().collect::<Vec<_>>();
        let lines = env.lines().collect::<Vec<_>>();
        let context_lines = context.lines().collect::<Vec<_>>();
        let barrier_lines = barrier.lines().collect::<Vec<_>>();
        let force_lines = force.lines().collect::<Vec<_>>();
        let native_call_lines = native_call.lines().collect::<Vec<_>>();

        assert_has_safety_comment_before(
            &native_call_lines,
            FINALIZED_CALL_JIT_BOUNDARY_LINE,
            "finalized native thunk-call jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &native_call_lines,
            CONTEXT_FINALIZED_CALL_JIT_BOUNDARY_LINE,
            "shared-context finalized native thunk-call jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &native_call_lines,
            CONTEXT_FINALIZED_LAMBDA_CALL_JIT_BOUNDARY_LINE,
            "shared-context finalized native lambda-call jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &native_call_lines,
            CONTEXT_FINALIZED_CHAIN_CALL_JIT_BOUNDARY_LINE,
            "shared-context finalized native chain-call jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &native_call_lines,
            CONTEXT_FINALIZED_FOLD_STEP_JIT_BOUNDARY_LINE,
            "shared-context finalized native fold-step jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &native_call_lines,
            CONTEXT_FINALIZED_FILTER_STEP_JIT_BOUNDARY_LINE,
            "shared-context finalized native filter-step jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &native_call_lines,
            CONTEXT_FINALIZED_ALL_ANY_STEP_JIT_BOUNDARY_LINE,
            "shared-context finalized native all/any-step jit boundary must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            ENV_GET_DECODER_CALL_LINE,
            "aos_env_get decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            UPVAL_GET_DECODER_CALL_LINE,
            "aos_upval_get decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            DIRECT_TEST_CALL_LINE,
            "direct wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            BINDING_TEST_CALL_LINE,
            "metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_CONTEXT_DECODER_LINE,
            "raw shared runtime context decoder must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_ENV_CONTEXT_DECODER_LINE,
            "raw shared runtime environment decoder must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_CONTEXT_CAST_LINE,
            "raw shared runtime context cast must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_ENV_CONTEXT_CAST_LINE,
            "raw shared runtime environment context cast must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_CONTEXT_EVAL_LINE,
            "raw shared runtime TreeWalk pointer cast must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_ENV_CONTEXT_EVAL_LINE,
            "raw shared runtime evaluator pointer must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &context_lines,
            RUNTIME_ENV_CONTEXT_ENV_LINE,
            "raw shared runtime environment pointer must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(&alloc_lines, ALLOC_CONS_DECODER_CALL_LINE, "cons allocation decoder call must keep a SAFETY comment");
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_ATTRS_ABORT_TEST_CALL_LINE,
            "attrset allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_CONS_ABORT_TEST_CALL_LINE,
            "cons allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_LAMBDA_ABORT_TEST_CALL_LINE,
            "lambda allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_LIST_ABORT_TEST_CALL_LINE,
            "list allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_RAW_ABORT_TEST_CALL_LINE,
            "raw allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_STRING_ABORT_TEST_CALL_LINE,
            "string allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &alloc_lines,
            ALLOC_THUNK_ABORT_TEST_CALL_LINE,
            "thunk allocation abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_DECODER_CALL_LINE,
            "apply decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_DIRECT_LAMBDA_TEST_CALL_LINE,
            "direct apply lambda wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_DIRECT_FUNCTOR_TEST_CALL_LINE,
            "direct apply functor wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_DIRECT_PRIMOP_PARTIAL_TEST_CALL_LINE,
            "direct apply primop partial wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_DIRECT_PRIMOP_RESULT_TEST_CALL_LINE,
            "direct apply primop result wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_BINDING_TEST_CALL_LINE,
            "apply metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_MALFORMED_VALUE_TRANSMUTE_LINE,
            "apply malformed Value construction test must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_MALFORMED_FUNCTION_ABORT_TEST_CALL_LINE,
            "apply malformed function abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_MALFORMED_ARGUMENT_ABORT_TEST_CALL_LINE,
            "apply malformed argument abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_NULL_CONTEXT_ABORT_TEST_CALL_LINE,
            "apply null-context abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &apply_lines,
            APPLY_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE,
            "apply tree-walk error abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_HAS_ATTR_DECODER_CALL_LINE,
            "has-attr decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_SELECT_IC_DECODER_CALL_LINE,
            "select-IC decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_UPDATE_DECODER_CALL_LINE,
            "attrset-update decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_HAS_ATTR_PRESENT_TEST_CALL_LINE,
            "direct has-attr presence test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_HAS_ATTR_REPEATED_TEST_CALL_LINE,
            "direct has-attr repeated test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_HAS_ATTR_MISSING_TEST_CALL_LINE,
            "direct has-attr missing test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_HAS_ATTR_NON_ATTRS_TEST_CALL_LINE,
            "direct has-attr non-attrs test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_SELECT_IC_SELECTED_TEST_CALL_LINE,
            "direct select-IC selected test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_SELECT_IC_REPEATED_TEST_CALL_LINE,
            "direct select-IC repeated test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_UPDATE_SUCCESS_TEST_CALL_LINE,
            "direct attrset-update success test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_SELECT_IC_ERROR_TEST_CALL_LINE,
            "select-IC tree-walk error abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_UPDATE_ERROR_TEST_CALL_LINE,
            "attrset-update tree-walk error abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_HAS_ATTR_ABORT_TEST_CALL_LINE,
            "has-attr abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_SELECT_IC_ABORT_TEST_CALL_LINE,
            "select-IC abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &attr_lines,
            ATTR_UPDATE_ABORT_TEST_CALL_LINE,
            "attrset-update abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &barrier_lines,
            WRITE_BARRIER_ABORT_TEST_CALL_LINE,
            "write-barrier abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_BLACKHOLE_TEST_CALL_LINE,
            "direct blackhole wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            BLACKHOLE_DECODER_CALL_LINE,
            "blackhole decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_DECODER_CALL_LINE,
            "force decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_DEEP_DECODER_CALL_LINE,
            "force-deep decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_TEST_CALL_LINE,
            "direct force wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_BLACKHOLE_THUNK_TEST_CALL_LINE,
            "direct blackhole thunk wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_THUNK_TEST_CALL_LINE,
            "direct force thunk wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_DEEP_TEST_CALL_LINE,
            "direct force-deep wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_DEEP_HEAP_TEST_CALL_LINE,
            "direct force-deep heap-leaf wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_DEEP_NESTED_TEST_CALL_LINE,
            "direct force-deep nested-container wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_DEEP_ATTRSET_TEST_CALL_LINE,
            "direct force-deep nested-attrset wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_BINDING_TEST_CALL_LINE,
            "force metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_DEEP_BINDING_TEST_CALL_LINE,
            "force-deep metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            BLACKHOLE_BINDING_TEST_CALL_LINE,
            "blackhole metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_MALFORMED_VALUE_TRANSMUTE_LINE,
            "malformed Value construction test must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_MALFORMED_ABORT_TEST_CALL_LINE,
            "malformed payload abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_NULL_CONTEXT_ABORT_TEST_CALL_LINE,
            "force null-context abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_THUNK_ABORT_TEST_CALL_LINE,
            "force tree-walk error abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_DEEP_MALFORMED_ABORT_TEST_CALL_LINE,
            "force-deep malformed payload abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_DEEP_NULL_CONTEXT_ABORT_TEST_CALL_LINE,
            "force-deep null-context abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_DEEP_TREE_WALK_ERROR_ABORT_TEST_CALL_LINE,
            "force-deep tree-walk error abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            BLACKHOLE_MALFORMED_ABORT_TEST_CALL_LINE,
            "blackhole malformed payload abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            BLACKHOLE_NULL_CONTEXT_ABORT_TEST_CALL_LINE,
            "blackhole null-context abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            BLACKHOLE_BLACKHOLED_ABORT_TEST_CALL_LINE,
            "blackhole blackholed-thunk abort test call must keep a SAFETY comment",
        );
    }

    fn assert_public_unsafe_docs(source_root: &Path) {
        let alloc = fs::read_to_string(source_root.join("alloc.rs"))
            .expect("allocation FFI source file is readable");
        let apply = fs::read_to_string(source_root.join("apply.rs"))
            .expect("apply FFI source file is readable");
        let attr = fs::read_to_string(source_root.join("attr.rs"))
            .expect("attrset-access FFI source file is readable");
        let env = fs::read_to_string(source_root.join("env.rs"))
            .expect("environment FFI source file is readable");
        let barrier = fs::read_to_string(source_root.join("barrier.rs"))
            .expect("write-barrier FFI source file is readable");
        let force =
            fs::read_to_string(source_root.join("force.rs")).expect("force FFI source is readable");
        let apply_lines = apply.lines().collect::<Vec<_>>();
        let alloc_lines = alloc.lines().collect::<Vec<_>>();
        let attr_lines = attr.lines().collect::<Vec<_>>();
        let lines = env.lines().collect::<Vec<_>>();
        let barrier_lines = barrier.lines().collect::<Vec<_>>();
        let force_lines = force.lines().collect::<Vec<_>>();

        assert_has_safety_doc_before(
            &lines,
            ENV_GET_FN_TYPE_LINE,
            "public native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &lines,
            ENV_GET_FN_LINE,
            "public native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_CODE_ENV_FN_TYPE_LINE,
            "public allocation code/env native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_ATTRS_FN_TYPE_LINE,
            "public allocation attrset native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_CONS_FN_TYPE_LINE,
            "public allocation cons native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_LEN_FN_TYPE_LINE,
            "public allocation length native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_RAW_FN_TYPE_LINE,
            "public allocation raw native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_ATTRS_FN_LINE,
            "public attrset allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_CONS_FN_LINE,
            "public cons allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_LAMBDA_FN_LINE,
            "public lambda allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_LIST_FN_LINE,
            "public list allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_RAW_FN_LINE,
            "public raw allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_STRING_FN_LINE,
            "public string allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &alloc_lines,
            ALLOC_THUNK_FN_LINE,
            "public thunk allocation native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &apply_lines,
            APPLY_FN_TYPE_LINE,
            "public apply native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &apply_lines,
            APPLY_FN_LINE,
            "public apply native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &attr_lines,
            ATTR_ACCESS_KEYED_FN_TYPE_LINE,
            "public keyed attrset native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &attr_lines,
            ATTR_UPDATE_FN_TYPE_LINE,
            "public attrset-update native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &attr_lines,
            ATTR_HAS_ATTR_FN_LINE,
            "public has-attr native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &attr_lines,
            ATTR_SELECT_IC_FN_LINE,
            "public select-IC native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &attr_lines,
            ATTR_UPDATE_FN_LINE,
            "public attrset-update native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &barrier_lines,
            WRITE_BARRIER_FN_TYPE_LINE,
            "public write-barrier native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &barrier_lines,
            WRITE_BARRIER_FN_LINE,
            "public write-barrier native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            BLACKHOLE_FN_TYPE_LINE,
            "public blackhole native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            FORCE_FN_TYPE_LINE,
            "public force native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            BLACKHOLE_FN_LINE,
            "public blackhole native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            FORCE_FN_LINE,
            "public force native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            FORCE_DEEP_FN_LINE,
            "public force-deep native wrapper must document # Safety",
        );
    }

    fn assert_has_safety_comment_before(lines: &[&str], expected: &str, message: &str) {
        let index = unique_line_index(lines, expected);
        let start = index.saturating_sub(3);
        assert!(
            lines[start..index].iter().any(|line| line
                .trim_start()
                .starts_with(RUNTIME_FFI_SAFETY_COMMENT_PREFIX)),
            "{message}"
        );
    }

    fn assert_has_safety_doc_before(lines: &[&str], expected: &str, message: &str) {
        let index = unique_line_index(lines, expected);
        let start = index.saturating_sub(18);
        assert!(
            lines[start..index]
                .iter()
                .any(|line| line.trim_start() == "/// # Safety"),
            "{message}"
        );
    }

    fn unique_line_index(lines: &[&str], expected: &str) -> usize {
        let matches = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| (line.trim_start() == expected).then_some(index))
            .collect::<Vec<_>>();

        assert_eq!(
            matches.len(),
            1,
            "expected exactly one reviewed line `{expected}`, found {}",
            matches.len()
        );
        matches[0]
    }

    fn trimmed_line_occurrences(source: &str, expected: &str) -> usize {
        source
            .lines()
            .filter(|line| line.trim_start() == expected)
            .count()
    }
}
