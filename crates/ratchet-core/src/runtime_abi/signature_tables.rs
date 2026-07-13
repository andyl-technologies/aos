//! Frozen native-call signature tables for the runtime ABI.
//!
//! The parameter lists and [`RuntimeCallSignature`] constants for compiled
//! thunk/lambda entries, the arity-indexed builtin primop wrappers, and every
//! core-owned runtime helper, plus their public accessors. The signatures are
//! frozen metadata: JIT lowering and the runtime FFI both derive their native
//! ABIs from these tables, so any edit is an ABI change.

use super::stack_map::{
    RUNTIME_JIT_STACK_MAP_ENTER_CALL_SIGNATURE, RUNTIME_JIT_STACK_MAP_EXIT_CALL_SIGNATURE,
};
use super::{
    RuntimeAbiCallingConvention, RuntimeAbiParameter, RuntimeAbiParameterKind,
    RuntimeAbiReturnKind, RuntimeCallAbiError, RuntimeCallSignature, RuntimeCallableKind,
    RuntimeHelperRole, RuntimeHelperSymbol,
};

/// The maximum builtin arity covered by the frozen primop ABI metadata today.
pub const MAX_RUNTIME_PRIMOP_ABI_ARITY: usize = 3;

pub(super) const THUNK_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
pub(super) const LAMBDA_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value),
];
const LAMBDA_ARGV_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("argv", RuntimeAbiParameterKind::RawPointer),
];
const PRIMOP_0_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
const PRIMOP_1_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("a0", RuntimeAbiParameterKind::Value),
];
const PRIMOP_2_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("a0", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("a1", RuntimeAbiParameterKind::Value),
];
const PRIMOP_3_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("a0", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("a1", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("a2", RuntimeAbiParameterKind::Value),
];

/// The frozen runtime-call signature for compiled thunk bodies.
pub const RUNTIME_THUNK_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::ThunkBody,
    RuntimeAbiCallingConvention::ExternC,
    THUNK_CALL_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

/// The frozen runtime-call signature for compiled lambda bodies.
pub const RUNTIME_LAMBDA_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::LambdaBody,
    RuntimeAbiCallingConvention::ExternC,
    LAMBDA_CALL_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

/// The frozen runtime-call signature for compiled multi-argument lambda entries.
///
/// A tier-2 fused curried-chain entry receives every argument of the chain at
/// once through `argv`: a caller-owned pointer to a contiguous run of by-value
/// runtime values (one 16-byte tag/payload pair per chain parameter, in
/// outermost-to-innermost order). One frozen shape serves every chain arity —
/// the compiled entry knows its own arity and loads exactly that many pairs —
/// and every word travels in a pointer register on both supported hosts, so no
/// aggregate-passing corner of the C ABI is exercised.
pub const RUNTIME_LAMBDA_ARGV_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::LambdaBody,
    RuntimeAbiCallingConvention::ExternC,
    LAMBDA_ARGV_CALL_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

const RUNTIME_PRIMOP_0_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 0 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_0_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_1_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 1 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_1_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_2_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 2 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_2_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_3_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Primop { arity: 3 },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_3_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

/// Frozen runtime-call signatures for builtin primop arities covered today.
pub const RUNTIME_PRIMOP_CALL_SIGNATURES: &[RuntimeCallSignature] = &[
    RUNTIME_PRIMOP_0_CALL_SIGNATURE,
    RUNTIME_PRIMOP_1_CALL_SIGNATURE,
    RUNTIME_PRIMOP_2_CALL_SIGNATURE,
    RUNTIME_PRIMOP_3_CALL_SIGNATURE,
];

const ALLOC_ATTRS_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("shape", RuntimeAbiParameterKind::ShapeId),
    RuntimeAbiParameter::new("slots", RuntimeAbiParameterKind::U32),
];
const ALLOC_CONS_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("head", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("tail", RuntimeAbiParameterKind::ListPointer),
];
const ALLOC_LAMBDA_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("code_ptr", RuntimeAbiParameterKind::CodePointer),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
const ALLOC_LIST_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("len", RuntimeAbiParameterKind::Usize),
];
const ALLOC_RAW_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("size", RuntimeAbiParameterKind::Usize),
    RuntimeAbiParameter::new("align", RuntimeAbiParameterKind::Usize),
    RuntimeAbiParameter::new("type_tag", RuntimeAbiParameterKind::TypeTag),
];
const ALLOC_STRING_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("len", RuntimeAbiParameterKind::Usize),
];
const ALLOC_THUNK_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("code_ptr", RuntimeAbiParameterKind::CodePointer),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
const GC_WRITE_BARRIER_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("thunk", RuntimeAbiParameterKind::ThunkPointer),
    RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
];
const ENV_GET_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("slot", RuntimeAbiParameterKind::U32),
];
const UPVAL_GET_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("depth", RuntimeAbiParameterKind::U32),
    RuntimeAbiParameter::new("slot", RuntimeAbiParameterKind::U32),
];
const FORCE_VALUE_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
];
const BLACKHOLE_CHECK_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
];
const APPLY_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("function", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value),
];
const DEOPT_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("deopt_record", RuntimeAbiParameterKind::DeoptRecordPointer),
];
const PRIMOP_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
    RuntimeAbiParameter::new("module_id", RuntimeAbiParameterKind::U32),
    RuntimeAbiParameter::new("node_id", RuntimeAbiParameterKind::U32),
];
const THROW_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("err", RuntimeAbiParameterKind::ErrorPointer),
];
const HAS_ATTR_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("attrs", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("symbol", RuntimeAbiParameterKind::SymbolId),
    RuntimeAbiParameter::new("site", RuntimeAbiParameterKind::InlineCacheSiteId),
];
const SELECT_IC_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("attrs", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("symbol", RuntimeAbiParameterKind::SymbolId),
    RuntimeAbiParameter::new("site", RuntimeAbiParameterKind::InlineCacheSiteId),
];
const UPDATE_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("left", RuntimeAbiParameterKind::Value),
    RuntimeAbiParameter::new("right", RuntimeAbiParameterKind::Value),
];

const RUNTIME_ALLOC_ATTRS_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_attrs", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_ATTRS_PARAMETERS,
    RuntimeAbiReturnKind::AttrsPointer,
);
const RUNTIME_ALLOC_CONS_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_cons", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_CONS_PARAMETERS,
    RuntimeAbiReturnKind::ListPointer,
);
const RUNTIME_ALLOC_LAMBDA_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_lambda", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_LAMBDA_PARAMETERS,
    RuntimeAbiReturnKind::LambdaPointer,
);
const RUNTIME_ALLOC_LIST_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_list", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_LIST_PARAMETERS,
    RuntimeAbiReturnKind::ListPointer,
);
const RUNTIME_ALLOC_RAW_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_raw", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_RAW_PARAMETERS,
    RuntimeAbiReturnKind::RawPointer,
);
const RUNTIME_ALLOC_STRING_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_string", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_STRING_PARAMETERS,
    RuntimeAbiReturnKind::StringHeaderPointer,
);
const RUNTIME_ALLOC_THUNK_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_alloc_thunk", RuntimeHelperRole::Allocation),
    },
    RuntimeAbiCallingConvention::ExternC,
    ALLOC_THUNK_PARAMETERS,
    RuntimeAbiReturnKind::ThunkPointer,
);
const RUNTIME_GC_WRITE_BARRIER_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_gc_write_barrier", RuntimeHelperRole::WriteBarrier),
    },
    RuntimeAbiCallingConvention::ExternC,
    GC_WRITE_BARRIER_PARAMETERS,
    RuntimeAbiReturnKind::Unit,
);
const RUNTIME_ENV_GET_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_env_get", RuntimeHelperRole::EnvironmentAccess),
    },
    RuntimeAbiCallingConvention::ExternC,
    ENV_GET_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_UPVAL_GET_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_upval_get", RuntimeHelperRole::EnvironmentAccess),
    },
    RuntimeAbiCallingConvention::ExternC,
    UPVAL_GET_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_FORCE_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_force", RuntimeHelperRole::ForcingControl),
    },
    RuntimeAbiCallingConvention::ExternC,
    FORCE_VALUE_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_FORCE_DEEP_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_force_deep", RuntimeHelperRole::ForcingControl),
    },
    RuntimeAbiCallingConvention::ExternC,
    FORCE_VALUE_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_BLACKHOLE_CHECK_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_blackhole_check", RuntimeHelperRole::ForcingControl),
    },
    RuntimeAbiCallingConvention::ExternC,
    BLACKHOLE_CHECK_PARAMETERS,
    RuntimeAbiReturnKind::Unit,
);
const RUNTIME_APPLY_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_apply", RuntimeHelperRole::CallControl),
    },
    RuntimeAbiCallingConvention::ExternC,
    APPLY_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_DEOPT_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_deopt", RuntimeHelperRole::Deoptimization),
    },
    RuntimeAbiCallingConvention::ExternC,
    DEOPT_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_PRIMOP_CALL_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_primop_call", RuntimeHelperRole::PrimopDispatch),
    },
    RuntimeAbiCallingConvention::ExternC,
    PRIMOP_CALL_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_STRING_LENGTH_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_string_length", RuntimeHelperRole::PrimopDispatch),
    },
    RuntimeAbiCallingConvention::ExternC,
    FORCE_VALUE_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_THROW_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_throw", RuntimeHelperRole::ErrorControl),
    },
    RuntimeAbiCallingConvention::ExternC,
    THROW_PARAMETERS,
    RuntimeAbiReturnKind::Diverges,
);
const RUNTIME_HAS_ATTR_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_has_attr", RuntimeHelperRole::AttrsetAccess),
    },
    RuntimeAbiCallingConvention::ExternC,
    HAS_ATTR_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_SELECT_IC_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_select_ic", RuntimeHelperRole::AttrsetAccess),
    },
    RuntimeAbiCallingConvention::ExternC,
    SELECT_IC_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);
const RUNTIME_UPDATE_CALL_SIGNATURE: RuntimeCallSignature = RuntimeCallSignature::new(
    RuntimeCallableKind::Helper {
        symbol: RuntimeHelperSymbol::new("aos_update", RuntimeHelperRole::AttrsetAccess),
    },
    RuntimeAbiCallingConvention::ExternC,
    UPDATE_PARAMETERS,
    RuntimeAbiReturnKind::Value,
);

/// Frozen helper call signatures for helpers with core-owned ABI shapes today.
pub const RUNTIME_HELPER_CALL_SIGNATURES: &[RuntimeCallSignature] = &[
    RUNTIME_ALLOC_ATTRS_CALL_SIGNATURE,
    RUNTIME_ALLOC_CONS_CALL_SIGNATURE,
    RUNTIME_ALLOC_LAMBDA_CALL_SIGNATURE,
    RUNTIME_ALLOC_LIST_CALL_SIGNATURE,
    RUNTIME_ALLOC_RAW_CALL_SIGNATURE,
    RUNTIME_ALLOC_STRING_CALL_SIGNATURE,
    RUNTIME_ALLOC_THUNK_CALL_SIGNATURE,
    RUNTIME_APPLY_CALL_SIGNATURE,
    RUNTIME_BLACKHOLE_CHECK_CALL_SIGNATURE,
    RUNTIME_DEOPT_CALL_SIGNATURE,
    RUNTIME_ENV_GET_CALL_SIGNATURE,
    RUNTIME_FORCE_CALL_SIGNATURE,
    RUNTIME_FORCE_DEEP_CALL_SIGNATURE,
    RUNTIME_GC_WRITE_BARRIER_CALL_SIGNATURE,
    RUNTIME_HAS_ATTR_CALL_SIGNATURE,
    RUNTIME_JIT_STACK_MAP_ENTER_CALL_SIGNATURE,
    RUNTIME_JIT_STACK_MAP_EXIT_CALL_SIGNATURE,
    RUNTIME_PRIMOP_CALL_CALL_SIGNATURE,
    RUNTIME_SELECT_IC_CALL_SIGNATURE,
    RUNTIME_STRING_LENGTH_CALL_SIGNATURE,
    RUNTIME_THROW_CALL_SIGNATURE,
    RUNTIME_UPDATE_CALL_SIGNATURE,
    RUNTIME_UPVAL_GET_CALL_SIGNATURE,
];

/// Returns the frozen runtime-call signature for compiled thunk bodies.
pub const fn runtime_thunk_call_signature() -> RuntimeCallSignature {
    RUNTIME_THUNK_CALL_SIGNATURE
}

/// Returns the frozen runtime-call signature for compiled lambda bodies.
pub const fn runtime_lambda_call_signature() -> RuntimeCallSignature {
    RUNTIME_LAMBDA_CALL_SIGNATURE
}

/// Returns the frozen runtime-call signature for multi-argument lambda entries.
///
/// See [`RUNTIME_LAMBDA_ARGV_CALL_SIGNATURE`] for the `argv` convention.
pub const fn runtime_lambda_argv_call_signature() -> RuntimeCallSignature {
    RUNTIME_LAMBDA_ARGV_CALL_SIGNATURE
}

/// Returns the frozen primop call-signature inventory.
pub const fn runtime_primop_call_signatures() -> &'static [RuntimeCallSignature] {
    RUNTIME_PRIMOP_CALL_SIGNATURES
}

/// Returns frozen helper call signatures whose ABI shapes are core-owned today.
pub const fn runtime_helper_call_signatures() -> &'static [RuntimeCallSignature] {
    RUNTIME_HELPER_CALL_SIGNATURES
}

/// Returns the frozen helper call signature for `symbol_name`, when known.
pub fn runtime_helper_call_signature(symbol_name: &str) -> Option<RuntimeCallSignature> {
    match symbol_name {
        "aos_alloc_attrs" => Some(RUNTIME_ALLOC_ATTRS_CALL_SIGNATURE),
        "aos_alloc_cons" => Some(RUNTIME_ALLOC_CONS_CALL_SIGNATURE),
        "aos_alloc_lambda" => Some(RUNTIME_ALLOC_LAMBDA_CALL_SIGNATURE),
        "aos_alloc_list" => Some(RUNTIME_ALLOC_LIST_CALL_SIGNATURE),
        "aos_alloc_raw" => Some(RUNTIME_ALLOC_RAW_CALL_SIGNATURE),
        "aos_alloc_string" => Some(RUNTIME_ALLOC_STRING_CALL_SIGNATURE),
        "aos_alloc_thunk" => Some(RUNTIME_ALLOC_THUNK_CALL_SIGNATURE),
        "aos_apply" => Some(RUNTIME_APPLY_CALL_SIGNATURE),
        "aos_deopt" => Some(RUNTIME_DEOPT_CALL_SIGNATURE),
        "aos_env_get" => Some(RUNTIME_ENV_GET_CALL_SIGNATURE),
        "aos_blackhole_check" => Some(RUNTIME_BLACKHOLE_CHECK_CALL_SIGNATURE),
        "aos_force" => Some(RUNTIME_FORCE_CALL_SIGNATURE),
        "aos_force_deep" => Some(RUNTIME_FORCE_DEEP_CALL_SIGNATURE),
        "aos_gc_write_barrier" => Some(RUNTIME_GC_WRITE_BARRIER_CALL_SIGNATURE),
        "aos_has_attr" => Some(RUNTIME_HAS_ATTR_CALL_SIGNATURE),
        "aos_jit_stack_map_enter" => Some(RUNTIME_JIT_STACK_MAP_ENTER_CALL_SIGNATURE),
        "aos_jit_stack_map_exit" => Some(RUNTIME_JIT_STACK_MAP_EXIT_CALL_SIGNATURE),
        "aos_primop_call" => Some(RUNTIME_PRIMOP_CALL_CALL_SIGNATURE),
        "aos_select_ic" => Some(RUNTIME_SELECT_IC_CALL_SIGNATURE),
        "aos_string_length" => Some(RUNTIME_STRING_LENGTH_CALL_SIGNATURE),
        "aos_update" => Some(RUNTIME_UPDATE_CALL_SIGNATURE),
        "aos_upval_get" => Some(RUNTIME_UPVAL_GET_CALL_SIGNATURE),
        "aos_throw" => Some(RUNTIME_THROW_CALL_SIGNATURE),
        _ => None,
    }
}

/// Returns the frozen primop call signature for `arity`.
///
/// # Errors
///
/// Returns [`RuntimeCallAbiError::UnsupportedPrimopArity`] when `arity` exceeds
/// [`MAX_RUNTIME_PRIMOP_ABI_ARITY`].
pub fn runtime_primop_call_signature(
    arity: usize,
) -> Result<RuntimeCallSignature, RuntimeCallAbiError> {
    match arity {
        0 => Ok(RUNTIME_PRIMOP_0_CALL_SIGNATURE),
        1 => Ok(RUNTIME_PRIMOP_1_CALL_SIGNATURE),
        2 => Ok(RUNTIME_PRIMOP_2_CALL_SIGNATURE),
        3 => Ok(RUNTIME_PRIMOP_3_CALL_SIGNATURE),
        _ => Err(RuntimeCallAbiError::UnsupportedPrimopArity {
            arity,
            max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
        }),
    }
}
