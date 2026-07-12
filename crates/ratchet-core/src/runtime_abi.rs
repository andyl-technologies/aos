//! Stable runtime ABI metadata for future native tiers.
//!
//! The safe tree-walk evaluator does not register Cranelift symbols, but the
//! compile metadata already owns the frozen names and call shapes that persisted
//! compiled-IR artifacts will reference. Builtins use `nix.builtin.<name>` and
//! runtime helpers use `aos_<verb>[_<qualifier>]`, matching RFC-0007 §10. The
//! call-signature descriptors in this module are contract metadata only; they do
//! not export wrappers, create raw-pointer call boundaries, or register a JIT
//! symbol table.

use std::{collections::BTreeSet, str};

use thiserror::Error;

use crate::builtins::BUILTINS;

mod stack_map;
mod value_layout;
use stack_map::{
    RUNTIME_JIT_STACK_MAP_ENTER_CALL_SIGNATURE, RUNTIME_JIT_STACK_MAP_EXIT_CALL_SIGNATURE,
};
pub use value_layout::{
    RuntimeAbiValueLayout, candidate_b_runtime_abi_value_layout,
    candidate_c_runtime_abi_value_layout, runtime_abi_value_layout,
};

/// The stable prefix for builtin runtime symbol names.
pub const BUILTIN_SYMBOL_PREFIX: &str = "nix.builtin.";

/// The stable prefix for non-builtin runtime helper symbols.
pub const RUNTIME_HELPER_SYMBOL_PREFIX: &str = "aos_";

/// A stable builtin runtime symbol name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinRuntimeSymbol {
    name: &'static [u8],
}

impl BuiltinRuntimeSymbol {
    /// Creates a stable runtime symbol view for a builtin declaration name.
    pub(crate) const fn new(name: &'static [u8]) -> Self {
        Self { name }
    }

    /// Returns the common `nix.builtin.` prefix.
    pub const fn prefix(self) -> &'static str {
        BUILTIN_SYMBOL_PREFIX
    }

    /// Returns the Nix-visible builtin name suffix.
    pub const fn builtin_name(self) -> &'static [u8] {
        self.name
    }

    /// Returns the stable symbol as owned text.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if the builtin
    /// name suffix cannot be represented as UTF-8 for a future string-keyed JIT
    /// symbol table.
    pub fn to_symbol_string(self) -> Result<String, RuntimeSymbolNameError> {
        let name = str::from_utf8(self.name).map_err(|source| {
            RuntimeSymbolNameError::NonUtf8BuiltinName {
                name: self.name.into(),
                source,
            }
        })?;
        let mut symbol = String::with_capacity(BUILTIN_SYMBOL_PREFIX.len() + name.len());
        symbol.push_str(BUILTIN_SYMBOL_PREFIX);
        symbol.push_str(name);
        Ok(symbol)
    }
}

/// A stable non-builtin runtime helper symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeHelperSymbol {
    name: &'static str,
    role: RuntimeHelperRole,
}

impl RuntimeHelperSymbol {
    /// Creates a stable runtime helper symbol declaration.
    const fn new(name: &'static str, role: RuntimeHelperRole) -> Self {
        Self { name, role }
    }

    /// Returns the symbol name that future native tiers register.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the runtime area served by this helper.
    pub const fn role(self) -> RuntimeHelperRole {
        self.role
    }
}

/// The runtime subsystem served by a stable helper symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperRole {
    /// Allocation helpers route heap object creation through the active GC.
    Allocation,
    /// Call helpers own generic apply/call entrypoints.
    CallControl,
    /// Deoptimization helpers return native execution to the interpreter.
    Deoptimization,
    /// Environment helpers load values from compiled closure environments.
    EnvironmentAccess,
    /// Forcing helpers own thunk forcing, deep forcing, and blackhole checks.
    ForcingControl,
    /// Write-barrier helpers own GC-visible heap mutation boundaries.
    WriteBarrier,
    /// Attribute helpers own select, presence, and update slow paths.
    AttrsetAccess,
    /// Error helpers own catch-frame and diagnostic control transfer.
    ErrorControl,
    /// Primop-dispatch helpers delegate a lowered builtin-call body back to the
    /// interpreter's builtin executor.
    PrimopDispatch,
    /// Safepoint helpers bind compiled-frame stack-map storage to the collector.
    SafepointControl,
}

/// Stable runtime helper symbols that compiled tiers may reference.
pub const RUNTIME_HELPER_SYMBOLS: &[RuntimeHelperSymbol] = &[
    RuntimeHelperSymbol::new("aos_alloc_attrs", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_cons", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_lambda", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_list", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_raw", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_string", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_alloc_thunk", RuntimeHelperRole::Allocation),
    RuntimeHelperSymbol::new("aos_apply", RuntimeHelperRole::CallControl),
    RuntimeHelperSymbol::new("aos_blackhole_check", RuntimeHelperRole::ForcingControl),
    RuntimeHelperSymbol::new("aos_deopt", RuntimeHelperRole::Deoptimization),
    RuntimeHelperSymbol::new("aos_env_get", RuntimeHelperRole::EnvironmentAccess),
    RuntimeHelperSymbol::new("aos_force", RuntimeHelperRole::ForcingControl),
    RuntimeHelperSymbol::new("aos_force_deep", RuntimeHelperRole::ForcingControl),
    RuntimeHelperSymbol::new("aos_gc_write_barrier", RuntimeHelperRole::WriteBarrier),
    RuntimeHelperSymbol::new("aos_has_attr", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_jit_stack_map_enter", RuntimeHelperRole::SafepointControl),
    RuntimeHelperSymbol::new("aos_jit_stack_map_exit", RuntimeHelperRole::SafepointControl),
    RuntimeHelperSymbol::new("aos_primop_call", RuntimeHelperRole::PrimopDispatch),
    RuntimeHelperSymbol::new("aos_select_ic", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_string_length", RuntimeHelperRole::PrimopDispatch),
    RuntimeHelperSymbol::new("aos_throw", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_try_begin", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_try_end", RuntimeHelperRole::ErrorControl),
    RuntimeHelperSymbol::new("aos_update", RuntimeHelperRole::AttrsetAccess),
    RuntimeHelperSymbol::new("aos_upval_get", RuntimeHelperRole::EnvironmentAccess),
];

/// Returns the frozen runtime helper symbol declarations.
pub const fn runtime_helper_symbols() -> &'static [RuntimeHelperSymbol] {
    RUNTIME_HELPER_SYMBOLS
}

/// The maximum builtin arity covered by the frozen primop ABI metadata today.
pub const MAX_RUNTIME_PRIMOP_ABI_ARITY: usize = 3;

const THUNK_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
];
const LAMBDA_CALL_PARAMETERS: &[RuntimeAbiParameter] = &[
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

/// The runtime callable family served by one native-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCallableKind {
    /// A compiled thunk body taking only runtime context and environment.
    ThunkBody,
    /// A compiled lambda body taking one already-applied Nix argument.
    LambdaBody,
    /// A builtin primop wrapper taking `arity` positional Nix arguments.
    Primop {
        /// The number of positional [`RuntimeAbiParameterKind::Value`] arguments.
        arity: usize,
    },
    /// A runtime helper registered under a stable `aos_*` symbol.
    Helper {
        /// The stable helper symbol served by this signature.
        symbol: RuntimeHelperSymbol,
    },
}

/// The machine calling convention promised by a runtime-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiCallingConvention {
    /// The platform C ABI reserved for future Cranelift and exported wrappers.
    ExternC,
}

/// One parameter in a frozen runtime-call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAbiParameter {
    name: &'static str,
    kind: RuntimeAbiParameterKind,
}

impl RuntimeAbiParameter {
    const fn new(name: &'static str, kind: RuntimeAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable parameter name used in ABI metadata.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level parameter kind.
    pub const fn kind(self) -> RuntimeAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by runtime-call signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiParameterKind {
    /// The mutable evaluator runtime context pointer.
    RuntimeContext,
    /// The captured environment frame pointer.
    EnvPointer,
    /// A pointer to tier deoptimization state reconstruction metadata.
    DeoptRecordPointer,
    /// A pointer to runtime-owned error payload metadata.
    ErrorPointer,
    /// A pointer to native code for a thunk or lambda body.
    CodePointer,
    /// A pointer to a runtime thunk object.
    ThunkPointer,
    /// A pointer to a runtime lambda closure object.
    LambdaPointer,
    /// A pointer to a runtime attrset object.
    AttrsPointer,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A pointer to a runtime string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
    /// A by-value runtime `Value` using [`runtime_abi_value_layout`].
    Value,
    /// A hidden-class shape identifier.
    ShapeId,
    /// A target-pointer-sized unsigned integer.
    Usize,
    /// A runtime-specific raw allocation type tag.
    TypeTag,
    /// A dense interned-symbol table index.
    SymbolId,
    /// A stable per-lookup inline-cache site identifier.
    InlineCacheSiteId,
    /// A 32-bit unsigned integer.
    U32,
}

/// The machine-level result kind returned by runtime-call signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAbiReturnKind {
    /// A by-value runtime `Value` using [`runtime_abi_value_layout`].
    Value,
    /// No machine-level result.
    Unit,
    /// Control does not return to the native caller.
    Diverges,
    /// A pointer to a runtime thunk object.
    ThunkPointer,
    /// A pointer to a runtime lambda closure object.
    LambdaPointer,
    /// A pointer to a runtime attrset object.
    AttrsPointer,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A pointer to a runtime string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
}

/// A frozen native-call signature for a runtime callable family.
///
/// This is safe metadata only. It describes the eventual `extern "C"` ABI that
/// Cranelift lowering and exported wrappers must agree on, but does not create
/// function pointers, exported symbols, or unsafe call boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCallSignature {
    callable: RuntimeCallableKind,
    convention: RuntimeAbiCallingConvention,
    parameters: &'static [RuntimeAbiParameter],
    return_kind: RuntimeAbiReturnKind,
}

impl RuntimeCallSignature {
    const fn new(
        callable: RuntimeCallableKind,
        convention: RuntimeAbiCallingConvention,
        parameters: &'static [RuntimeAbiParameter],
        return_kind: RuntimeAbiReturnKind,
    ) -> Self {
        Self {
            callable,
            convention,
            parameters,
            return_kind,
        }
    }

    /// Returns the runtime callable family served by this signature.
    pub const fn callable(self) -> RuntimeCallableKind {
        self.callable
    }

    /// Returns the machine calling convention used by this signature.
    pub const fn convention(self) -> RuntimeAbiCallingConvention {
        self.convention
    }

    /// Returns the ordered ABI parameters.
    pub const fn parameters(self) -> &'static [RuntimeAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind.
    pub const fn return_kind(self) -> RuntimeAbiReturnKind {
        self.return_kind
    }
}

/// A failure while selecting runtime-call ABI metadata.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RuntimeCallAbiError {
    /// The requested primop arity has no frozen native-call signature today.
    #[error("primop arity {arity} exceeds the frozen runtime ABI maximum {max}")]
    UnsupportedPrimopArity {
        /// The requested primop arity.
        arity: usize,
        /// The largest primop arity described by the current ABI metadata.
        max: usize,
    },
}

/// Result returned when building builtin runtime-call manifest metadata.
pub type RuntimeBuiltinCallManifestResult =
    Result<Vec<RuntimeBuiltinCallManifestEntry>, RuntimeSymbolNameError>;

/// Builds the stable builtin runtime-call manifest.
///
/// The manifest preserves sorted `nix.builtin.*` symbol order and classifies
/// each builtin as a callable primop wrapper, a value-only builtin, or a builtin
/// whose declared arity has no frozen native-call signature yet. This is safe
/// ABI-contract metadata only; it does not export builtin wrappers or install
/// JIT symbols.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if a builtin suffix is
/// not valid UTF-8.
pub fn runtime_builtin_call_manifest() -> RuntimeBuiltinCallManifestResult {
    let mut entries = Vec::with_capacity(BUILTINS.len());

    for builtin in BUILTINS.iter().copied() {
        entries.push(RuntimeBuiltinCallManifestEntry::new(
            builtin.runtime_symbol().to_symbol_string()?,
            builtin.name(),
            RuntimeBuiltinCallStatus::from_first_class_arity(builtin.first_class_arity()),
        ));
    }

    entries.sort_by(|left, right| left.symbol_name.cmp(&right.symbol_name));
    Ok(entries)
}

/// Result returned when building builtin runtime-call preflight metadata.
pub type RuntimeBuiltinCallPreflightResult =
    Result<RuntimeBuiltinCallPreflight, RuntimeSymbolNameError>;

/// Builds callable builtin runtime-call readiness metadata.
///
/// Callable builtin symbols receive their frozen primop call signature. Builtin
/// value symbols and unsupported arities are reported as gaps so later native
/// registration cannot silently treat them as executable wrappers.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if the builtin call
/// manifest cannot be built.
pub fn runtime_builtin_call_preflight() -> RuntimeBuiltinCallPreflightResult {
    let mut call_bindings = Vec::new();
    let mut missing_bindings = Vec::new();

    for entry in runtime_builtin_call_manifest()? {
        match entry.status() {
            RuntimeBuiltinCallStatus::Callable { arity, signature } => {
                call_bindings.push(RuntimeBuiltinCallBinding::new(
                    entry.symbol_name().to_owned(),
                    entry.builtin_name(),
                    arity,
                    signature,
                ));
            }
            RuntimeBuiltinCallStatus::ValueOnly => {
                missing_bindings.push(RuntimeBuiltinCallMissingBinding::value_only(
                    entry.symbol_name().to_owned(),
                    entry.builtin_name(),
                ));
            }
            RuntimeBuiltinCallStatus::UnsupportedArity { arity, max } => {
                missing_bindings.push(RuntimeBuiltinCallMissingBinding::unsupported_arity_gap(
                    entry.symbol_name().to_owned(),
                    entry.builtin_name(),
                    arity,
                    max,
                ));
            }
        }
    }

    Ok(RuntimeBuiltinCallPreflight::new(
        call_bindings,
        missing_bindings,
    ))
}

/// The current runtime-call status for one builtin symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBuiltinCallStatus {
    /// A callable builtin wrapper with a frozen primop call signature.
    Callable {
        /// The first-class builtin arity served by the wrapper.
        arity: usize,
        /// The native-call signature reserved for this arity.
        signature: RuntimeCallSignature,
    },
    /// A builtin value symbol such as `true`, `false`, `null`, or `builtins`.
    ValueOnly,
    /// A callable builtin whose arity exceeds the frozen metadata inventory.
    UnsupportedArity {
        /// The declared first-class builtin arity.
        arity: usize,
        /// The largest primop arity described by current metadata.
        max: usize,
    },
}

impl RuntimeBuiltinCallStatus {
    fn from_first_class_arity(first_class_arity: Option<usize>) -> Self {
        match first_class_arity {
            Some(arity) => match runtime_primop_call_signature(arity) {
                Ok(signature) => Self::Callable { arity, signature },
                Err(RuntimeCallAbiError::UnsupportedPrimopArity { max, .. }) => {
                    Self::UnsupportedArity { arity, max }
                }
            },
            None => Self::ValueOnly,
        }
    }
}

/// One builtin symbol and its current runtime-call status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBuiltinCallManifestEntry {
    symbol_name: String,
    builtin_name: &'static [u8],
    status: RuntimeBuiltinCallStatus,
}

impl RuntimeBuiltinCallManifestEntry {
    fn new(
        symbol_name: String,
        builtin_name: &'static [u8],
        status: RuntimeBuiltinCallStatus,
    ) -> Self {
        Self {
            symbol_name,
            builtin_name,
            status,
        }
    }

    /// Returns the stable `nix.builtin.*` runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the byte-oriented builtin declaration name.
    pub const fn builtin_name(&self) -> &'static [u8] {
        self.builtin_name
    }

    /// Returns the current runtime-call status for this builtin symbol.
    pub const fn status(&self) -> RuntimeBuiltinCallStatus {
        self.status
    }
}

/// A callable builtin runtime-call binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBuiltinCallBinding {
    symbol_name: String,
    builtin_name: &'static [u8],
    arity: usize,
    signature: RuntimeCallSignature,
}

impl RuntimeBuiltinCallBinding {
    fn new(
        symbol_name: String,
        builtin_name: &'static [u8],
        arity: usize,
        signature: RuntimeCallSignature,
    ) -> Self {
        Self {
            symbol_name,
            builtin_name,
            arity,
            signature,
        }
    }

    /// Returns the stable `nix.builtin.*` runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the byte-oriented builtin declaration name.
    pub const fn builtin_name(&self) -> &'static [u8] {
        self.builtin_name
    }

    /// Returns the first-class builtin arity served by this binding.
    pub const fn arity(&self) -> usize {
        self.arity
    }

    /// Returns the native-call signature reserved for this builtin binding.
    pub const fn signature(&self) -> RuntimeCallSignature {
        self.signature
    }
}

/// One builtin symbol that does not yet have a callable runtime binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeBuiltinCallMissingBinding {
    /// The builtin is a value symbol rather than a callable primop wrapper.
    ValueOnly {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
        /// The byte-oriented builtin declaration name.
        builtin_name: &'static [u8],
    },
    /// The builtin declares an arity without a frozen call signature.
    UnsupportedArity {
        /// The stable `nix.builtin.*` runtime symbol name.
        symbol_name: String,
        /// The byte-oriented builtin declaration name.
        builtin_name: &'static [u8],
        /// The declared first-class builtin arity.
        arity: usize,
        /// The largest primop arity described by current metadata.
        max: usize,
    },
}

impl RuntimeBuiltinCallMissingBinding {
    fn value_only(symbol_name: String, builtin_name: &'static [u8]) -> Self {
        Self::ValueOnly {
            symbol_name,
            builtin_name,
        }
    }

    fn unsupported_arity_gap(
        symbol_name: String,
        builtin_name: &'static [u8],
        arity: usize,
        max: usize,
    ) -> Self {
        Self::UnsupportedArity {
            symbol_name,
            builtin_name,
            arity,
            max,
        }
    }

    /// Returns the stable `nix.builtin.*` runtime symbol name.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::ValueOnly { symbol_name, .. } | Self::UnsupportedArity { symbol_name, .. } => {
                symbol_name
            }
        }
    }

    /// Returns the byte-oriented builtin declaration name.
    pub const fn builtin_name(&self) -> &'static [u8] {
        match self {
            Self::ValueOnly { builtin_name, .. } | Self::UnsupportedArity { builtin_name, .. } => {
                builtin_name
            }
        }
    }

    /// Returns the unsupported arity when this gap is arity-related.
    pub const fn unsupported_arity(&self) -> Option<usize> {
        match self {
            Self::UnsupportedArity { arity, .. } => Some(*arity),
            Self::ValueOnly { .. } => None,
        }
    }
}

/// A deterministic readiness report for callable builtin runtime symbols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBuiltinCallPreflight {
    call_bindings: Vec<RuntimeBuiltinCallBinding>,
    missing_bindings: Vec<RuntimeBuiltinCallMissingBinding>,
}

impl RuntimeBuiltinCallPreflight {
    fn new(
        call_bindings: Vec<RuntimeBuiltinCallBinding>,
        missing_bindings: Vec<RuntimeBuiltinCallMissingBinding>,
    ) -> Self {
        Self {
            call_bindings,
            missing_bindings,
        }
    }

    /// Returns callable builtin bindings in stable symbol order.
    pub fn call_bindings(&self) -> &[RuntimeBuiltinCallBinding] {
        &self.call_bindings
    }

    /// Returns builtin symbols that do not yet have callable bindings.
    pub fn missing_bindings(&self) -> &[RuntimeBuiltinCallMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every builtin symbol has a callable runtime binding.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }
}

/// The runtime symbol family served by a manifest entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolKind {
    /// A non-builtin helper registered under an `aos_*` symbol.
    Helper(RuntimeHelperRole),
    /// A Nix builtin registered under a `nix.builtin.*` symbol.
    Builtin,
}

/// One stable runtime symbol that future native tiers register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolManifestEntry {
    name: String,
    kind: RuntimeSymbolKind,
}

impl RuntimeSymbolManifestEntry {
    fn new(name: String, kind: RuntimeSymbolKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable symbol name registered with a native symbol table.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the runtime symbol family served by this entry.
    pub const fn kind(&self) -> RuntimeSymbolKind {
        self.kind
    }
}

/// Builds the stable runtime symbol manifest for future native tiers.
///
/// The manifest combines all `aos_*` helper symbols and all declared
/// `nix.builtin.*` builtin symbols into one deterministic, lexicographically
/// sorted table. Future `JITBuilder::symbol` registration can consume this
/// manifest before attaching executable addresses from the active runtime.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError::NonUtf8BuiltinName`] if a builtin suffix is
/// not valid UTF-8. Returns [`RuntimeSymbolNameError::DuplicateRuntimeSymbol`]
/// if the combined helper and builtin inventories contain the same final symbol
/// name more than once.
pub fn runtime_symbol_manifest() -> Result<Vec<RuntimeSymbolManifestEntry>, RuntimeSymbolNameError>
{
    let mut entries = Vec::with_capacity(runtime_helper_symbols().len() + BUILTINS.len());
    let mut seen = BTreeSet::new();

    for helper in runtime_helper_symbols().iter().copied() {
        push_manifest_entry(
            &mut entries,
            &mut seen,
            RuntimeSymbolManifestEntry::new(
                helper.name().to_owned(),
                RuntimeSymbolKind::Helper(helper.role()),
            ),
        )?;
    }

    for builtin in BUILTINS.iter().copied() {
        push_manifest_entry(
            &mut entries,
            &mut seen,
            RuntimeSymbolManifestEntry::new(
                builtin.runtime_symbol().to_symbol_string()?,
                RuntimeSymbolKind::Builtin,
            ),
        )?;
    }

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn push_manifest_entry(
    entries: &mut Vec<RuntimeSymbolManifestEntry>,
    seen: &mut BTreeSet<String>,
    entry: RuntimeSymbolManifestEntry,
) -> Result<(), RuntimeSymbolNameError> {
    if !seen.insert(entry.name.clone()) {
        return Err(RuntimeSymbolNameError::DuplicateRuntimeSymbol { symbol: entry.name });
    }
    entries.push(entry);
    Ok(())
}

/// An invalid stable runtime symbol name.
#[derive(Clone, Debug, Error)]
pub enum RuntimeSymbolNameError {
    /// A builtin declaration name was not valid UTF-8.
    #[error("builtin runtime symbol suffix {name:?} is not valid UTF-8")]
    NonUtf8BuiltinName {
        /// The invalid builtin name bytes.
        name: Box<[u8]>,
        /// The UTF-8 validation failure.
        #[source]
        source: str::Utf8Error,
    },
    /// A final runtime symbol name appeared more than once.
    #[error("runtime symbol {symbol:?} appears more than once")]
    DuplicateRuntimeSymbol {
        /// The duplicated final symbol name.
        symbol: String,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::builtins::BUILTINS;

    use super::*;

    #[test]
    fn builtin_runtime_symbols_use_frozen_prefix_and_visible_names() {
        assert_eq!(
            BUILTINS
                .lookup(b"derivationStrict")
                .expect("derivationStrict is registered")
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin name is UTF-8"),
            "nix.builtin.derivationStrict"
        );
        assert_eq!(
            BUILTINS
                .lookup(b"foldl'")
                .expect("foldl' is registered")
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin name is UTF-8"),
            "nix.builtin.foldl'"
        );

        for builtin in BUILTINS.iter().copied() {
            let symbol = builtin
                .runtime_symbol()
                .to_symbol_string()
                .expect("declared builtin names are UTF-8");
            assert!(symbol.starts_with(BUILTIN_SYMBOL_PREFIX), "{symbol}");
            assert_eq!(
                &symbol.as_bytes()[BUILTIN_SYMBOL_PREFIX.len()..],
                builtin.name()
            );
        }
    }

    #[test]
    fn builtin_runtime_symbol_rejects_non_utf8_suffixes() {
        let error = BuiltinRuntimeSymbol::new(b"\xff")
            .to_symbol_string()
            .expect_err("invalid UTF-8 is rejected");

        assert!(matches!(
            error,
            RuntimeSymbolNameError::NonUtf8BuiltinName { .. }
        ));
    }

    #[test]
    fn runtime_helper_symbols_are_unique_sorted_and_prefixed() {
        let mut previous = None;
        let mut seen = BTreeSet::new();

        for symbol in runtime_helper_symbols() {
            assert!(symbol.name().starts_with(RUNTIME_HELPER_SYMBOL_PREFIX));
            assert!(
                seen.insert(symbol.name()),
                "{} appears twice",
                symbol.name()
            );
            if let Some(previous) = previous {
                assert!(
                    previous < symbol.name(),
                    "{previous} before {}",
                    symbol.name()
                );
            }
            previous = Some(symbol.name());
        }
    }

    #[test]
    fn runtime_helper_symbols_include_single_write_barrier_wall() {
        let write_barriers = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::WriteBarrier)
            .map(RuntimeHelperSymbol::name)
            .collect::<BTreeSet<_>>();

        assert_eq!(write_barriers, BTreeSet::from(["aos_gc_write_barrier"]));
    }

    #[test]
    fn runtime_call_metadata_pins_value_layout_and_convention() {
        let value_layout = runtime_abi_value_layout();

        // The by-value layout tracks the selected carrier (two-word on the
        // baseline, one-word under the `candidate_c_value` variant).
        #[cfg(not(feature = "candidate_c_value"))]
        {
            assert_eq!(value_layout.size_bytes(), 16);
            assert_eq!(value_layout.register_words(), 2);
        }
        #[cfg(feature = "candidate_c_value")]
        {
            assert_eq!(value_layout.size_bytes(), 8);
            assert_eq!(value_layout.register_words(), 1);
        }
        assert_eq!(value_layout.register_word_bytes(), 8);

        let mut signatures = vec![
            runtime_thunk_call_signature(),
            runtime_lambda_call_signature(),
        ];
        signatures.extend(runtime_primop_call_signatures().iter().copied());

        for signature in signatures {
            assert_eq!(signature.convention(), RuntimeAbiCallingConvention::ExternC);
            assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
            assert_eq!(
                signature.parameters()[0],
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext)
            );
            assert_eq!(
                signature.parameters()[1],
                RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer)
            );
        }
    }

    #[test]
    fn thunk_and_lambda_call_signatures_share_runtime_prefix() {
        let thunk = runtime_thunk_call_signature();
        let lambda = runtime_lambda_call_signature();

        assert_eq!(thunk.callable(), RuntimeCallableKind::ThunkBody);
        assert_eq!(thunk.parameters(), THUNK_CALL_PARAMETERS);
        assert_eq!(thunk.parameters().len(), 2);

        assert_eq!(lambda.callable(), RuntimeCallableKind::LambdaBody);
        assert_eq!(lambda.parameters(), LAMBDA_CALL_PARAMETERS);
        assert_eq!(lambda.parameters().len(), 3);
        assert_eq!(
            lambda.parameters()[2],
            RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value)
        );
    }

    #[test]
    fn primop_call_signatures_cover_declared_builtin_arities() {
        let max_declared_arity = BUILTINS
            .iter()
            .filter_map(|builtin| builtin.first_class_arity())
            .max()
            .expect("first-class builtins exist");

        assert_eq!(MAX_RUNTIME_PRIMOP_ABI_ARITY, 3);
        assert!(max_declared_arity <= MAX_RUNTIME_PRIMOP_ABI_ARITY);
        assert_eq!(
            runtime_primop_call_signatures().len(),
            MAX_RUNTIME_PRIMOP_ABI_ARITY + 1
        );

        for arity in 0..=MAX_RUNTIME_PRIMOP_ABI_ARITY {
            let signature = runtime_primop_call_signature(arity).expect("arity is covered");
            assert_eq!(signature.callable(), RuntimeCallableKind::Primop { arity });
            assert_eq!(signature.parameters().len(), arity + 2);
            for (index, parameter) in signature.parameters().iter().copied().enumerate() {
                match index {
                    0 => assert_eq!(
                        parameter,
                        RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext)
                    ),
                    1 => assert_eq!(
                        parameter,
                        RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer)
                    ),
                    argument_index => {
                        let expected_name = format!("a{}", argument_index - 2);
                        assert_eq!(
                            parameter.name(),
                            expected_name.as_str(),
                            "primop argument names stay positional"
                        );
                        assert_eq!(parameter.kind(), RuntimeAbiParameterKind::Value);
                    }
                }
            }
        }
    }

    #[test]
    fn primop_call_signature_rejects_unfrozen_arities() {
        let error = runtime_primop_call_signature(MAX_RUNTIME_PRIMOP_ABI_ARITY + 1)
            .expect_err("unsupported arity rejects");

        assert_eq!(
            error,
            RuntimeCallAbiError::UnsupportedPrimopArity {
                arity: MAX_RUNTIME_PRIMOP_ABI_ARITY + 1,
                max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
            }
        );
    }

    #[test]
    fn allocation_helper_call_signatures_pin_scalars_and_pointer_results() {
        let attrs = runtime_helper_call_signature("aos_alloc_attrs")
            .expect("attrs allocation signature is core-owned");
        let thunk = runtime_helper_call_signature("aos_alloc_thunk")
            .expect("thunk allocation signature is core-owned");
        let raw = runtime_helper_call_signature("aos_alloc_raw")
            .expect("raw allocation signature is core-owned");

        assert_eq!(
            attrs.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new("aos_alloc_attrs", RuntimeHelperRole::Allocation),
            }
        );
        assert_eq!(
            attrs.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("shape", RuntimeAbiParameterKind::ShapeId),
                RuntimeAbiParameter::new("slots", RuntimeAbiParameterKind::U32),
            ]
        );
        assert_eq!(attrs.return_kind(), RuntimeAbiReturnKind::AttrsPointer);

        assert_eq!(
            thunk.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("code_ptr", RuntimeAbiParameterKind::CodePointer),
                RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
            ]
        );
        assert_eq!(thunk.return_kind(), RuntimeAbiReturnKind::ThunkPointer);

        assert_eq!(
            raw.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("size", RuntimeAbiParameterKind::Usize),
                RuntimeAbiParameter::new("align", RuntimeAbiParameterKind::Usize),
                RuntimeAbiParameter::new("type_tag", RuntimeAbiParameterKind::TypeTag),
            ]
        );
        assert_eq!(raw.return_kind(), RuntimeAbiReturnKind::RawPointer);
    }

    #[test]
    fn call_control_helper_call_signature_pins_apply_value_boundary() {
        let apply =
            runtime_helper_call_signature("aos_apply").expect("apply signature is core-owned");

        assert_eq!(
            apply.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new("aos_apply", RuntimeHelperRole::CallControl),
            }
        );
        assert_eq!(
            apply.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("function", RuntimeAbiParameterKind::Value),
                RuntimeAbiParameter::new("arg", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(apply.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn deoptimization_helper_call_signature_pins_record_pointer_boundary() {
        let deopt =
            runtime_helper_call_signature("aos_deopt").expect("deopt signature is core-owned");

        assert_eq!(
            deopt.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new("aos_deopt", RuntimeHelperRole::Deoptimization),
            }
        );
        assert_eq!(
            deopt.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new(
                    "deopt_record",
                    RuntimeAbiParameterKind::DeoptRecordPointer,
                ),
            ]
        );
        assert_eq!(deopt.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn error_helper_call_signature_pins_throw_divergence() {
        let throw =
            runtime_helper_call_signature("aos_throw").expect("throw signature is core-owned");

        assert_eq!(
            throw.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new("aos_throw", RuntimeHelperRole::ErrorControl),
            }
        );
        assert_eq!(
            throw.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("err", RuntimeAbiParameterKind::ErrorPointer),
            ]
        );
        assert_eq!(throw.return_kind(), RuntimeAbiReturnKind::Diverges);
    }

    #[test]
    fn forcing_helper_call_signatures_pin_whnf_value_boundary() {
        let force =
            runtime_helper_call_signature("aos_force").expect("force signature is core-owned");
        let force_deep = runtime_helper_call_signature("aos_force_deep")
            .expect("deep-force signature is core-owned");
        let blackhole_check = runtime_helper_call_signature("aos_blackhole_check")
            .expect("blackhole-check signature is core-owned");

        for (symbol_name, signature) in [("aos_force", force), ("aos_force_deep", force_deep)] {
            assert_eq!(
                signature.callable(),
                RuntimeCallableKind::Helper {
                    symbol: RuntimeHelperSymbol::new(
                        symbol_name,
                        RuntimeHelperRole::ForcingControl,
                    ),
                }
            );
            assert_eq!(
                signature.parameters(),
                &[
                    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                    RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
                ]
            );
            assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
        }

        assert_eq!(
            blackhole_check.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(
                    "aos_blackhole_check",
                    RuntimeHelperRole::ForcingControl,
                ),
            }
        );
        assert_eq!(
            blackhole_check.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(blackhole_check.return_kind(), RuntimeAbiReturnKind::Unit);
    }

    #[test]
    fn attrset_helper_call_signatures_pin_static_key_value_boundaries() {
        let has_attr = runtime_helper_call_signature("aos_has_attr")
            .expect("has-attr signature is core-owned");
        let select_ic = runtime_helper_call_signature("aos_select_ic")
            .expect("select-IC signature is core-owned");

        for (symbol_name, signature) in [("aos_has_attr", has_attr), ("aos_select_ic", select_ic)] {
            assert_eq!(
                signature.callable(),
                RuntimeCallableKind::Helper {
                    symbol: RuntimeHelperSymbol::new(symbol_name, RuntimeHelperRole::AttrsetAccess,),
                }
            );
            assert_eq!(
                signature.parameters(),
                &[
                    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                    RuntimeAbiParameter::new("attrs", RuntimeAbiParameterKind::Value),
                    RuntimeAbiParameter::new("symbol", RuntimeAbiParameterKind::SymbolId),
                    RuntimeAbiParameter::new("site", RuntimeAbiParameterKind::InlineCacheSiteId),
                ]
            );
            assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
        }

        let update =
            runtime_helper_call_signature("aos_update").expect("update signature is core-owned");
        assert_eq!(
            update.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new("aos_update", RuntimeHelperRole::AttrsetAccess,),
            }
        );
        assert_eq!(
            update.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("left", RuntimeAbiParameterKind::Value),
                RuntimeAbiParameter::new("right", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(update.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn write_barrier_helper_call_signature_pins_unit_return() {
        let signature = runtime_helper_call_signature("aos_gc_write_barrier")
            .expect("write-barrier signature is core-owned");

        assert_eq!(
            signature.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(
                    "aos_gc_write_barrier",
                    RuntimeHelperRole::WriteBarrier,
                ),
            }
        );
        assert_eq!(
            signature.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("thunk", RuntimeAbiParameterKind::ThunkPointer),
                RuntimeAbiParameter::new("value", RuntimeAbiParameterKind::Value),
            ]
        );
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Unit);
    }

    #[test]
    fn env_get_helper_call_signature_pins_slot_lookup_value_return() {
        let signature =
            runtime_helper_call_signature("aos_env_get").expect("env-get signature is core-owned");

        assert_eq!(
            signature.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(
                    "aos_env_get",
                    RuntimeHelperRole::EnvironmentAccess,
                ),
            }
        );
        assert_eq!(
            signature.parameters(),
            &[
                RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
                RuntimeAbiParameter::new("slot", RuntimeAbiParameterKind::U32),
            ]
        );
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn upval_get_helper_call_signature_pins_depth_slot_lookup_value_return() {
        let signature = runtime_helper_call_signature("aos_upval_get")
            .expect("upval-get signature is core-owned");

        assert_eq!(
            signature.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(
                    "aos_upval_get",
                    RuntimeHelperRole::EnvironmentAccess,
                ),
            }
        );
        assert_eq!(
            signature.parameters(),
            &[
                RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
                RuntimeAbiParameter::new("depth", RuntimeAbiParameterKind::U32),
                RuntimeAbiParameter::new("slot", RuntimeAbiParameterKind::U32),
            ]
        );
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn primop_call_helper_call_signature_pins_rt_env_module_node_value_return() {
        let signature = runtime_helper_call_signature("aos_primop_call")
            .expect("primop-call signature is core-owned");

        assert_eq!(
            signature.callable(),
            RuntimeCallableKind::Helper {
                symbol: RuntimeHelperSymbol::new(
                    "aos_primop_call",
                    RuntimeHelperRole::PrimopDispatch,
                ),
            }
        );
        assert_eq!(
            signature.parameters(),
            &[
                RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
                RuntimeAbiParameter::new("env", RuntimeAbiParameterKind::EnvPointer),
                RuntimeAbiParameter::new("module_id", RuntimeAbiParameterKind::U32),
                RuntimeAbiParameter::new("node_id", RuntimeAbiParameterKind::U32),
            ]
        );
        assert_eq!(signature.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn builtin_call_manifest_preserves_runtime_builtin_symbol_order() {
        let runtime_builtin_symbols = runtime_symbol_manifest()
            .expect("runtime manifest builds")
            .into_iter()
            .filter(|entry| entry.kind() == RuntimeSymbolKind::Builtin)
            .map(|entry| entry.name().to_owned())
            .collect::<Vec<_>>();
        let call_manifest = runtime_builtin_call_manifest().expect("builtin call manifest builds");

        assert_eq!(
            call_manifest
                .iter()
                .map(RuntimeBuiltinCallManifestEntry::symbol_name)
                .collect::<Vec<_>>(),
            runtime_builtin_symbols
        );
    }

    #[test]
    fn builtin_call_manifest_marks_callable_and_value_only_builtins() {
        let manifest = runtime_builtin_call_manifest().expect("builtin call manifest builds");

        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == "nix.builtin.derivationStrict")
                .map(RuntimeBuiltinCallManifestEntry::status),
            Some(RuntimeBuiltinCallStatus::Callable {
                arity: 1,
                signature: runtime_primop_call_signature(1).expect("arity 1 is frozen"),
            })
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.symbol_name() == "nix.builtin.foldl'")
                .map(RuntimeBuiltinCallManifestEntry::status),
            Some(RuntimeBuiltinCallStatus::Callable {
                arity: 3,
                signature: runtime_primop_call_signature(3).expect("arity 3 is frozen"),
            })
        );
        for symbol_name in [
            "nix.builtin.builtins",
            "nix.builtin.false",
            "nix.builtin.null",
            "nix.builtin.true",
        ] {
            assert_eq!(
                manifest
                    .iter()
                    .find(|entry| entry.symbol_name() == symbol_name)
                    .map(RuntimeBuiltinCallManifestEntry::status),
                Some(RuntimeBuiltinCallStatus::ValueOnly),
                "{symbol_name} stays a value-only builtin symbol"
            );
        }
    }

    #[test]
    fn builtin_call_preflight_reports_current_value_only_gaps() {
        let preflight = runtime_builtin_call_preflight().expect("builtin call preflight builds");
        let callable_count = BUILTINS
            .iter()
            .filter(|builtin| builtin.first_class_arity().is_some())
            .count();
        let value_only_count = BUILTINS
            .iter()
            .filter(|builtin| builtin.first_class_arity().is_none())
            .count();

        assert!(!preflight.is_complete());
        assert_eq!(preflight.call_bindings().len(), callable_count);
        assert_eq!(preflight.missing_bindings().len(), value_only_count);
        assert!(
            preflight
                .missing_bindings()
                .iter()
                .all(|missing| missing.unsupported_arity().is_none())
        );
        assert!(preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == "nix.builtin.true" && missing.builtin_name() == b"true"
        }));

        for binding in preflight.call_bindings() {
            let builtin = BUILTINS
                .lookup(binding.builtin_name())
                .expect("call binding names a declared builtin");
            let expected_symbol = builtin
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin symbol is UTF-8");
            assert_eq!(binding.symbol_name(), expected_symbol);
            assert_eq!(Some(binding.arity()), builtin.first_class_arity());
            assert_eq!(
                binding.signature(),
                runtime_primop_call_signature(binding.arity()).expect("binding arity is frozen")
            );
        }
    }

    #[test]
    fn builtin_call_status_reports_future_unsupported_arities() {
        assert_eq!(
            RuntimeBuiltinCallStatus::from_first_class_arity(Some(
                MAX_RUNTIME_PRIMOP_ABI_ARITY + 1
            )),
            RuntimeBuiltinCallStatus::UnsupportedArity {
                arity: MAX_RUNTIME_PRIMOP_ABI_ARITY + 1,
                max: MAX_RUNTIME_PRIMOP_ABI_ARITY,
            }
        );
    }

    #[test]
    fn runtime_symbol_manifest_combines_helpers_and_builtins() {
        let manifest = runtime_symbol_manifest().expect("manifest builds");

        assert_eq!(
            manifest.len(),
            runtime_helper_symbols().len() + BUILTINS.len()
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == "aos_gc_write_barrier")
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Helper(RuntimeHelperRole::WriteBarrier))
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == "nix.builtin.derivationStrict")
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Builtin)
        );
        assert_eq!(
            manifest
                .iter()
                .find(|entry| entry.name() == "nix.builtin.foldl'")
                .map(RuntimeSymbolManifestEntry::kind),
            Some(RuntimeSymbolKind::Builtin)
        );

        for helper in runtime_helper_symbols().iter().copied() {
            assert_eq!(
                manifest
                    .iter()
                    .find(|entry| entry.name() == helper.name())
                    .map(RuntimeSymbolManifestEntry::kind),
                Some(RuntimeSymbolKind::Helper(helper.role())),
                "{} helper appears in the manifest",
                helper.name()
            );
        }

        for builtin in BUILTINS.iter().copied() {
            let symbol = builtin
                .runtime_symbol()
                .to_symbol_string()
                .expect("builtin symbol is UTF-8");
            assert_eq!(
                manifest
                    .iter()
                    .find(|entry| entry.name() == symbol)
                    .map(RuntimeSymbolManifestEntry::kind),
                Some(RuntimeSymbolKind::Builtin),
                "{symbol} builtin appears in the manifest"
            );
        }
    }

    #[test]
    fn runtime_symbol_manifest_is_sorted_and_unique() {
        let manifest = runtime_symbol_manifest().expect("manifest builds");
        let mut previous = None;
        let mut seen = BTreeSet::new();

        for entry in &manifest {
            assert!(
                seen.insert(entry.name().to_owned()),
                "{} appears twice",
                entry.name()
            );
            if let Some(previous) = previous {
                assert!(
                    previous < entry.name(),
                    "{previous} before {}",
                    entry.name()
                );
            }
            previous = Some(entry.name());
        }
    }

    #[test]
    fn runtime_symbol_manifest_rejects_duplicates_before_registration() {
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        let duplicate = RuntimeSymbolManifestEntry::new(
            "aos_duplicate".to_owned(),
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
        );

        push_manifest_entry(&mut entries, &mut seen, duplicate.clone())
            .expect("first symbol records");
        let error = push_manifest_entry(&mut entries, &mut seen, duplicate)
            .expect_err("duplicate symbol rejects");

        assert!(matches!(
            error,
            RuntimeSymbolNameError::DuplicateRuntimeSymbol { .. }
        ));
        assert_eq!(entries.len(), 1);
    }
}
