//! Address-free runtime ABI inventory, native entry aliases, and CLIF adapters.
//!
//! The inventory in this module mirrors the safe runtime ABI metadata owned by
//! `ratchet-core`. It gives JIT-side code a local, documented entry point for the
//! thunk, lambda, builtin primop, and core-owned helper call signatures. The
//! native entry aliases name the future unsafe call boundary for compiled thunk
//! and lambda bodies without constructing any function pointer values. The CLIF
//! adapter lowers those frozen call signatures to Cranelift [`Signature`] values
//! only; it does not construct a Cranelift module, register symbols, emit code,
//! cast code pointers, or call native addresses.

use std::{error::Error, ffi::c_void, fmt};

use cranelift_codegen::{
    ir::{AbiParam, Signature, Type, types},
    isa::CallConv,
};
use ratchet_core::{
    RuntimeAbiCallingConvention, RuntimeAbiParameter, RuntimeAbiParameterKind,
    RuntimeAbiReturnKind, RuntimeAbiValueLayout, RuntimeCallSignature,
    candidate_c_runtime_abi_value_layout, runtime_abi_value_layout, runtime_helper_call_signatures,
    runtime_lambda_call_signature, runtime_primop_call_signatures, runtime_thunk_call_signature,
};
use ratchet_value::value::Value;
use target_lexicon::{CallingConvention, Triple};

const RUNTIME_VALUE_CLIF_WORD_BYTES: usize = 8;
const RUNTIME_VALUE_CLIF_MAX_WORDS: usize = 2;

/// Opaque pointer to evaluator runtime context state passed to compiled code.
///
/// This is a raw ABI pointer placeholder only. The pointed-to layout and
/// lifetime model remain owned by future runtime-wrapper work; safe preflights
/// must not dereference it.
pub type JitRuntimeContextPtr = *mut c_void;

/// Opaque pointer to a captured environment frame passed to compiled code.
///
/// This is a raw ABI pointer placeholder only. The frame layout, borrow
/// discipline, and root tracking remain future runtime-wrapper work; safe
/// preflights must not dereference it.
pub type JitEnvFramePtr = *mut c_void;

/// Native entry type for a compiled thunk body.
///
/// The signature is the concrete Rust type-level counterpart of
/// [`runtime_thunk_call_signature`]: `extern "C"` calling convention, runtime
/// context pointer, environment pointer, and one by-value runtime [`Value`]
/// result. Calling a value of this type is unsafe because it crosses into
/// compiled code with raw pointers and evaluator-owned state. This alias does
/// not create, cast, register, or call any function pointer.
pub type JitThunkFn = unsafe extern "C" fn(JitRuntimeContextPtr, JitEnvFramePtr) -> Value;

/// Native entry type for a Candidate-C one-word compiled thunk body.
///
/// Calling this type is unsafe for the same raw-pointer and executable-code
/// lifetime reasons as [`JitThunkFn`]. The returned integer is validated as a
/// compressed word after the call.
pub type JitCandidateCThunkFn =
    unsafe extern "C" fn(JitRuntimeContextPtr, JitEnvFramePtr) -> u64;

/// Native entry type for a compiled lambda body.
///
/// The signature is the concrete Rust type-level counterpart of
/// [`runtime_lambda_call_signature`]: `extern "C"` calling convention, runtime
/// context pointer, environment pointer, one already-applied by-value runtime
/// [`Value`] argument, and one by-value runtime [`Value`] result. Calling a
/// value of this type is unsafe because it crosses into compiled code with raw
/// pointers and evaluator-owned state. This alias does not create, cast,
/// register, or call any function pointer.
pub type JitLambdaFn = unsafe extern "C" fn(JitRuntimeContextPtr, JitEnvFramePtr, Value) -> Value;

/// Native entry type for a compiled multi-argument (curried-chain) lambda entry.
///
/// The signature is the concrete Rust type-level counterpart of
/// [`runtime_lambda_argv_call_signature`]: `extern "C"` calling convention,
/// runtime context pointer, environment pointer, and a caller-owned pointer to
/// a contiguous run of by-value runtime [`Value`] arguments (one 16-byte
/// tag/payload pair per chain parameter, outermost first). The compiled entry
/// knows its own arity and loads exactly that many pairs, so one frozen shape
/// serves every chain arity without exercising aggregate-passing corners of
/// the C ABI. Calling a value of this type is unsafe because it crosses into
/// compiled code with raw pointers and evaluator-owned state. This alias does
/// not create, cast, register, or call any function pointer.
///
/// [`runtime_lambda_argv_call_signature`]: ratchet_core::runtime_lambda_argv_call_signature
pub type JitLambdaArgvFn = unsafe extern "C" fn(JitRuntimeContextPtr, JitEnvFramePtr, *const Value) -> Value;

/// Address-free runtime-call signatures required by JIT lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JitRuntimeAbiInventory {
    thunk_body: RuntimeCallSignature,
    lambda_body: RuntimeCallSignature,
    primop_wrappers: Vec<RuntimeCallSignature>,
    helper_wrappers: Vec<RuntimeCallSignature>,
}

impl JitRuntimeAbiInventory {
    /// Builds the JIT-side ABI inventory from the core metadata source of truth.
    pub fn from_core_metadata() -> Self {
        Self {
            thunk_body: runtime_thunk_call_signature(),
            lambda_body: runtime_lambda_call_signature(),
            primop_wrappers: runtime_primop_call_signatures().to_vec(),
            helper_wrappers: runtime_helper_call_signatures().to_vec(),
        }
    }

    /// Returns the frozen runtime-call signature for compiled thunk bodies.
    pub const fn thunk_body_signature(&self) -> RuntimeCallSignature {
        self.thunk_body
    }

    /// Returns the frozen runtime-call signature for compiled lambda bodies.
    pub const fn lambda_body_signature(&self) -> RuntimeCallSignature {
        self.lambda_body
    }

    /// Returns frozen builtin primop wrapper signatures in arity order.
    pub fn primop_wrapper_signatures(&self) -> &[RuntimeCallSignature] {
        &self.primop_wrappers
    }

    /// Returns frozen helper call signatures with core-owned ABI shapes.
    pub fn helper_wrapper_signatures(&self) -> &[RuntimeCallSignature] {
        &self.helper_wrappers
    }
}

/// Returns the JIT-side view of the frozen runtime-call ABI metadata.
pub fn jit_runtime_abi_inventory() -> JitRuntimeAbiInventory {
    JitRuntimeAbiInventory::from_core_metadata()
}

/// Converts a frozen runtime-call signature into a Cranelift function signature.
///
/// Runtime context, environment, code, and heap-object pointer parameters become
/// host-pointer-sized CLIF parameters. Each by-value runtime `Value` parameter
/// or result is expanded to the active one- or two-word `i64` ABI shape recorded
/// by `ratchet-core`; fixed `u32`-sized fields lower to `i32`, and `usize`
/// lowers to the host pointer type.
///
/// # Errors
///
/// Returns [`JitClifSignatureError::UnsupportedRuntimeValueLayout`] if the
/// frozen runtime `Value` ABI is not one or two 8-byte words. Returns
/// [`JitClifSignatureError::UnsupportedHostPointerWidth`] if the host target is
/// neither 32-bit nor 64-bit. Returns
/// [`JitClifSignatureError::UnsupportedHostCallingConvention`] if the host target
/// reports a C ABI that this adapter cannot lower without relying on a Cranelift
/// panic path.
pub fn clif_signature_for_runtime_call(
    signature: RuntimeCallSignature,
) -> Result<Signature, JitClifSignatureError> {
    clif_signature_for_runtime_call_with_layout(signature, runtime_abi_value_layout())
}

/// Converts a frozen runtime-call signature using Candidate C's one-word values.
///
/// # Errors
///
/// Returns the same target and layout errors as
/// [`clif_signature_for_runtime_call`].
pub fn clif_signature_for_candidate_c_runtime_call(
    signature: RuntimeCallSignature,
) -> Result<Signature, JitClifSignatureError> {
    clif_signature_for_runtime_call_with_layout(
        signature,
        candidate_c_runtime_abi_value_layout(),
    )
}

fn clif_signature_for_runtime_call_with_layout(
    signature: RuntimeCallSignature,
    value_layout: RuntimeAbiValueLayout,
) -> Result<Signature, JitClifSignatureError> {
    validate_runtime_value_layout(value_layout)?;

    let mut clif_signature = Signature::new(clif_call_conv_for(signature.convention())?);
    let pointer_type = host_pointer_type()?;

    for parameter in signature.parameters() {
        append_parameter(
            &mut clif_signature.params,
            *parameter,
            pointer_type,
            value_layout,
        );
    }
    append_return_kind(
        &mut clif_signature.returns,
        signature.return_kind(),
        pointer_type,
        value_layout,
    );

    Ok(clif_signature)
}

/// A failure while converting frozen runtime-call metadata to CLIF signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JitClifSignatureError {
    /// The runtime `Value` ABI is not one or two 8-byte words.
    UnsupportedRuntimeValueLayout {
        /// The observed by-value `Value` size in bytes.
        size_bytes: usize,
        /// The observed number of register-passed words.
        register_words: usize,
        /// The observed byte width of each register-passed word.
        register_word_bytes: usize,
    },
    /// The host pointer width is not representable by the current adapter.
    UnsupportedHostPointerWidth {
        /// The host pointer width reported by the Rust target.
        pointer_width_bits: u32,
    },
    /// The host target reports a C calling convention unsupported by this adapter.
    UnsupportedHostCallingConvention {
        /// The target-lexicon calling convention name.
        calling_convention: &'static str,
    },
}

impl fmt::Display for JitClifSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRuntimeValueLayout {
                size_bytes,
                register_words,
                register_word_bytes,
            } => write!(
                formatter,
                "runtime Value ABI layout {size_bytes} bytes, {register_words} register words, \
                 {register_word_bytes} bytes per word is not lowerable as one or two Cranelift \
                 i64 words"
            ),
            Self::UnsupportedHostPointerWidth { pointer_width_bits } => write!(
                formatter,
                "host pointer width {pointer_width_bits} bits is not supported by the CLIF ABI adapter"
            ),
            Self::UnsupportedHostCallingConvention { calling_convention } => write!(
                formatter,
                "host calling convention {calling_convention} is not supported by the CLIF ABI adapter"
            ),
        }
    }
}

impl Error for JitClifSignatureError {}

fn clif_call_conv_for(
    convention: RuntimeAbiCallingConvention,
) -> Result<CallConv, JitClifSignatureError> {
    match convention {
        RuntimeAbiCallingConvention::ExternC => clif_default_call_conv_for_triple(&Triple::host()),
    }
}

fn clif_default_call_conv_for_triple(triple: &Triple) -> Result<CallConv, JitClifSignatureError> {
    match triple.default_calling_convention() {
        Ok(CallingConvention::SystemV) | Err(()) => Ok(CallConv::SystemV),
        Ok(CallingConvention::AppleAarch64) => Ok(CallConv::AppleAarch64),
        Ok(CallingConvention::WindowsFastcall) => Ok(CallConv::WindowsFastcall),
        Ok(convention) => Err(JitClifSignatureError::UnsupportedHostCallingConvention {
            calling_convention: calling_convention_name(convention),
        }),
    }
}

fn calling_convention_name(convention: CallingConvention) -> &'static str {
    match convention {
        CallingConvention::SystemV => "SystemV",
        CallingConvention::WasmBasicCAbi => "WasmBasicCAbi",
        CallingConvention::WindowsFastcall => "WindowsFastcall",
        CallingConvention::AppleAarch64 => "AppleAarch64",
        _ => "unknown",
    }
}

fn host_pointer_type() -> Result<Type, JitClifSignatureError> {
    match usize::BITS {
        32 => Ok(types::I32),
        64 => Ok(types::I64),
        pointer_width_bits => {
            Err(JitClifSignatureError::UnsupportedHostPointerWidth { pointer_width_bits })
        }
    }
}

fn append_parameter(
    params: &mut Vec<AbiParam>,
    parameter: RuntimeAbiParameter,
    pointer_type: Type,
    value_layout: RuntimeAbiValueLayout,
) {
    match parameter.kind() {
        RuntimeAbiParameterKind::RuntimeContext
        | RuntimeAbiParameterKind::EnvPointer
        | RuntimeAbiParameterKind::DeoptRecordPointer
        | RuntimeAbiParameterKind::ErrorPointer
        | RuntimeAbiParameterKind::CodePointer
        | RuntimeAbiParameterKind::ThunkPointer
        | RuntimeAbiParameterKind::LambdaPointer
        | RuntimeAbiParameterKind::AttrsPointer
        | RuntimeAbiParameterKind::ListPointer
        | RuntimeAbiParameterKind::StringHeaderPointer
        | RuntimeAbiParameterKind::RawPointer => {
            params.push(AbiParam::new(pointer_type));
        }
        RuntimeAbiParameterKind::Value => append_value_words(params, value_layout),
        RuntimeAbiParameterKind::ShapeId
        | RuntimeAbiParameterKind::SymbolId
        | RuntimeAbiParameterKind::InlineCacheSiteId
        | RuntimeAbiParameterKind::TypeTag
        | RuntimeAbiParameterKind::U32 => params.push(AbiParam::new(types::I32)),
        RuntimeAbiParameterKind::Usize => params.push(AbiParam::new(pointer_type)),
    }
}

fn append_return_kind(
    returns: &mut Vec<AbiParam>,
    return_kind: RuntimeAbiReturnKind,
    pointer_type: Type,
    value_layout: RuntimeAbiValueLayout,
) {
    match return_kind {
        RuntimeAbiReturnKind::Value => append_value_words(returns, value_layout),
        RuntimeAbiReturnKind::Unit | RuntimeAbiReturnKind::Diverges => {}
        RuntimeAbiReturnKind::ThunkPointer
        | RuntimeAbiReturnKind::LambdaPointer
        | RuntimeAbiReturnKind::AttrsPointer
        | RuntimeAbiReturnKind::ListPointer
        | RuntimeAbiReturnKind::StringHeaderPointer
        | RuntimeAbiReturnKind::RawPointer => returns.push(AbiParam::new(pointer_type)),
    }
}

fn append_value_words(params: &mut Vec<AbiParam>, layout: RuntimeAbiValueLayout) {
    for _ in 0..layout.register_words() {
        params.push(AbiParam::new(types::I64));
    }
}

fn validate_runtime_value_layout(
    layout: RuntimeAbiValueLayout,
) -> Result<(), JitClifSignatureError> {
    let observed = ObservedRuntimeValueLayout::from(layout);
    validate_observed_value_layout(observed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObservedRuntimeValueLayout {
    size_bytes: usize,
    register_words: usize,
    register_word_bytes: usize,
}

impl From<RuntimeAbiValueLayout> for ObservedRuntimeValueLayout {
    fn from(layout: RuntimeAbiValueLayout) -> Self {
        Self {
            size_bytes: layout.size_bytes(),
            register_words: layout.register_words(),
            register_word_bytes: layout.register_word_bytes(),
        }
    }
}

fn validate_observed_value_layout(
    layout: ObservedRuntimeValueLayout,
) -> Result<(), JitClifSignatureError> {
    if (1..=RUNTIME_VALUE_CLIF_MAX_WORDS).contains(&layout.register_words)
        && layout.register_word_bytes == RUNTIME_VALUE_CLIF_WORD_BYTES
        && layout
            .register_words
            .checked_mul(layout.register_word_bytes)
            == Some(layout.size_bytes)
    {
        return Ok(());
    }

    Err(JitClifSignatureError::UnsupportedRuntimeValueLayout {
        size_bytes: layout.size_bytes,
        register_words: layout.register_words,
        register_word_bytes: layout.register_word_bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::mem;

    use cranelift_codegen::ir::{Type, types};
    use ratchet_core::{
        RuntimeCallableKind, RuntimeHelperRole, candidate_c_runtime_abi_value_layout,
        runtime_abi_value_layout, runtime_helper_call_signature, runtime_helper_call_signatures,
        runtime_lambda_call_signature, runtime_primop_call_signature,
        runtime_primop_call_signatures, runtime_thunk_call_signature,
    };

    use super::*;

    #[test]
    fn jit_runtime_abi_inventory_mirrors_core_call_metadata() {
        let inventory = jit_runtime_abi_inventory();

        assert_eq!(
            inventory.thunk_body_signature(),
            runtime_thunk_call_signature()
        );
        assert_eq!(
            inventory.lambda_body_signature(),
            runtime_lambda_call_signature()
        );
        assert_eq!(
            inventory.primop_wrapper_signatures(),
            runtime_primop_call_signatures()
        );
        assert_eq!(
            inventory.helper_wrapper_signatures(),
            runtime_helper_call_signatures()
        );
    }

    #[test]
    fn jit_runtime_abi_inventory_preserves_callable_kinds() {
        let inventory = jit_runtime_abi_inventory();
        let primop_arities = inventory
            .primop_wrapper_signatures()
            .iter()
            .map(|signature| signature.callable())
            .collect::<Vec<_>>();

        assert_eq!(
            inventory.thunk_body_signature().callable(),
            RuntimeCallableKind::ThunkBody
        );
        assert_eq!(
            inventory.lambda_body_signature().callable(),
            RuntimeCallableKind::LambdaBody
        );
        assert_eq!(
            primop_arities,
            vec![
                RuntimeCallableKind::Primop { arity: 0 },
                RuntimeCallableKind::Primop { arity: 1 },
                RuntimeCallableKind::Primop { arity: 2 },
                RuntimeCallableKind::Primop { arity: 3 },
            ]
        );
        assert!(
            inventory
                .helper_wrapper_signatures()
                .iter()
                .any(|signature| matches!(
                    signature.callable(),
                    RuntimeCallableKind::Helper { symbol }
                        if symbol.name() == "aos_alloc_attrs"
                            && symbol.role() == RuntimeHelperRole::Allocation
                ))
        );
    }

    #[test]
    fn native_entry_aliases_remain_pointer_sized_beside_core_metadata() {
        let thunk_signature = runtime_thunk_call_signature();
        let lambda_signature = runtime_lambda_call_signature();

        assert_eq!(
            mem::size_of::<Value>(),
            runtime_abi_value_layout().size_bytes()
        );
        assert_eq!(
            mem::size_of::<JitRuntimeContextPtr>(),
            mem::size_of::<usize>()
        );
        assert_eq!(mem::size_of::<JitEnvFramePtr>(), mem::size_of::<usize>());
        assert_eq!(mem::size_of::<JitThunkFn>(), mem::size_of::<usize>());
        assert_eq!(mem::size_of::<JitLambdaFn>(), mem::size_of::<usize>());
        assert_eq!(
            thunk_signature.convention(),
            RuntimeAbiCallingConvention::ExternC
        );
        assert_eq!(
            thunk_signature
                .parameters()
                .iter()
                .map(|parameter| parameter.kind())
                .collect::<Vec<_>>(),
            vec![
                RuntimeAbiParameterKind::RuntimeContext,
                RuntimeAbiParameterKind::EnvPointer
            ]
        );
        assert_eq!(thunk_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            lambda_signature.convention(),
            RuntimeAbiCallingConvention::ExternC
        );
        assert_eq!(
            lambda_signature
                .parameters()
                .iter()
                .map(|parameter| parameter.kind())
                .collect::<Vec<_>>(),
            vec![
                RuntimeAbiParameterKind::RuntimeContext,
                RuntimeAbiParameterKind::EnvPointer,
                RuntimeAbiParameterKind::Value
            ]
        );
        assert_eq!(lambda_signature.return_kind(), RuntimeAbiReturnKind::Value);
    }

    #[test]
    fn thunk_body_clif_signature_uses_pointer_params_and_value_return_words() {
        let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())
            .expect("thunk signature uses the pinned runtime value layout");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(
            signature.call_conv,
            clif_call_conv_for(RuntimeAbiCallingConvention::ExternC)
                .expect("host target has a supported C calling convention")
        );
        assert_eq!(param_types(&signature), vec![pointer_type, pointer_type]);
        assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
    }

    #[test]
    fn lambda_body_clif_signature_expands_value_argument() {
        let signature = clif_signature_for_runtime_call(runtime_lambda_call_signature())
            .expect("lambda signature uses the pinned runtime value layout");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(
            param_types(&signature),
            vec![pointer_type, pointer_type, types::I64, types::I64]
        );
        assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
    }

    #[test]
    fn primop_clif_signatures_expand_each_value_argument_by_arity() {
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        for arity in 0..=3 {
            let runtime_signature =
                runtime_primop_call_signature(arity).expect("arity is covered by frozen metadata");
            let signature = clif_signature_for_runtime_call(runtime_signature)
                .expect("primop signature uses the pinned runtime value layout");

            let mut expected_params = vec![pointer_type, pointer_type];
            for _ in 0..arity {
                expected_params.push(types::I64);
                expected_params.push(types::I64);
            }

            assert_eq!(param_types(&signature), expected_params);
            assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
        }
    }

    #[test]
    fn allocation_helper_clif_signature_lowers_scalars_and_pointer_return() {
        let runtime_signature = runtime_helper_call_signature("aos_alloc_attrs")
            .expect("allocation helper signature is core-owned");
        let signature = clif_signature_for_runtime_call(runtime_signature)
            .expect("allocation helper signature lowers");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(
            runtime_signature.return_kind(),
            RuntimeAbiReturnKind::AttrsPointer
        );
        assert_eq!(
            param_types(&signature),
            vec![pointer_type, types::I32, types::I32]
        );
        assert_eq!(return_types(&signature), vec![pointer_type]);
    }

    #[test]
    fn write_barrier_helper_clif_signature_lowers_value_and_unit_return() {
        let runtime_signature = runtime_helper_call_signature("aos_gc_write_barrier")
            .expect("write-barrier helper signature is core-owned");
        let signature = clif_signature_for_runtime_call(runtime_signature)
            .expect("write-barrier helper signature lowers");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(runtime_signature.return_kind(), RuntimeAbiReturnKind::Unit);
        assert_eq!(
            param_types(&signature),
            vec![pointer_type, pointer_type, types::I64, types::I64]
        );
        assert!(return_types(&signature).is_empty());
    }

    #[test]
    fn env_get_helper_clif_signature_lowers_env_slot_and_value_return() {
        let runtime_signature = runtime_helper_call_signature("aos_env_get")
            .expect("env-get helper signature is core-owned");
        let signature =
            clif_signature_for_runtime_call(runtime_signature).expect("env-get signature lowers");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(runtime_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(param_types(&signature), vec![pointer_type, types::I32]);
        assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
    }

    #[test]
    fn force_helper_clif_signature_lowers_value_argument_and_return_boundaries() {
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        for symbol_name in ["aos_force", "aos_force_deep"] {
            let runtime_signature =
                runtime_helper_call_signature(symbol_name).expect("force signature is core-owned");
            let signature =
                clif_signature_for_runtime_call(runtime_signature).expect("force signature lowers");

            assert_eq!(runtime_signature.return_kind(), RuntimeAbiReturnKind::Value);
            assert_eq!(
                param_types(&signature),
                vec![pointer_type, types::I64, types::I64]
            );
            assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
        }

        let blackhole_check = runtime_helper_call_signature("aos_blackhole_check")
            .expect("blackhole-check signature is core-owned");
        let blackhole_check_signature = clif_signature_for_runtime_call(blackhole_check)
            .expect("blackhole-check signature lowers");

        assert_eq!(blackhole_check.return_kind(), RuntimeAbiReturnKind::Unit);
        assert_eq!(
            param_types(&blackhole_check_signature),
            vec![pointer_type, types::I64, types::I64]
        );
        assert!(return_types(&blackhole_check_signature).is_empty());
    }

    #[test]
    fn apply_helper_clif_signature_lowers_value_arguments_and_return() {
        let runtime_signature =
            runtime_helper_call_signature("aos_apply").expect("apply signature is core-owned");
        let signature =
            clif_signature_for_runtime_call(runtime_signature).expect("apply signature lowers");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(runtime_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            param_types(&signature),
            vec![pointer_type, types::I64, types::I64, types::I64, types::I64]
        );
        assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
    }

    #[test]
    fn deopt_helper_clif_signature_lowers_record_pointer_and_value_return() {
        let runtime_signature =
            runtime_helper_call_signature("aos_deopt").expect("deopt signature is core-owned");
        let signature =
            clif_signature_for_runtime_call(runtime_signature).expect("deopt signature lowers");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(runtime_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(param_types(&signature), vec![pointer_type, pointer_type]);
        assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
    }

    #[test]
    fn attrset_access_helper_clif_signatures_lower_symbol_and_site_ids() {
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        for symbol_name in ["aos_has_attr", "aos_select_ic"] {
            let runtime_signature = runtime_helper_call_signature(symbol_name)
                .expect("attrset signature is core-owned");
            let signature = clif_signature_for_runtime_call(runtime_signature)
                .expect("attrset signature lowers");

            assert_eq!(runtime_signature.return_kind(), RuntimeAbiReturnKind::Value);
            assert_eq!(
                param_types(&signature),
                vec![pointer_type, types::I64, types::I64, types::I32, types::I32]
            );
            assert_eq!(return_types(&signature), vec![types::I64, types::I64]);
        }

        let update_signature =
            runtime_helper_call_signature("aos_update").expect("update signature is core-owned");
        let update_clif_signature =
            clif_signature_for_runtime_call(update_signature).expect("update signature lowers");

        assert_eq!(update_signature.return_kind(), RuntimeAbiReturnKind::Value);
        assert_eq!(
            param_types(&update_clif_signature),
            vec![pointer_type, types::I64, types::I64, types::I64, types::I64]
        );
        assert_eq!(
            return_types(&update_clif_signature),
            vec![types::I64, types::I64]
        );
    }

    #[test]
    fn throw_helper_clif_signature_lowers_error_pointer_and_no_return_slots() {
        let runtime_signature =
            runtime_helper_call_signature("aos_throw").expect("throw signature is core-owned");
        let signature =
            clif_signature_for_runtime_call(runtime_signature).expect("throw signature lowers");
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");

        assert_eq!(
            runtime_signature.return_kind(),
            RuntimeAbiReturnKind::Diverges
        );
        assert_eq!(param_types(&signature), vec![pointer_type, pointer_type]);
        assert!(return_types(&signature).is_empty());
    }

    #[test]
    fn unsupported_host_calling_convention_reports_error() {
        let wasm_triple = "wasm32-wasi"
            .parse::<Triple>()
            .expect("target-lexicon parses wasm32-wasi");

        let error = clif_default_call_conv_for_triple(&wasm_triple)
            .expect_err("wasm Basic C ABI is not a supported native JIT calling convention");
        assert_eq!(
            error,
            JitClifSignatureError::UnsupportedHostCallingConvention {
                calling_convention: "WasmBasicCAbi",
            }
        );
    }

    #[test]
    fn runtime_value_layout_guard_accepts_baseline_and_candidate_c_words() {
        let layout = runtime_abi_value_layout();

        assert_eq!(layout.size_bytes(), 16);
        assert_eq!(layout.register_words(), 2);
        assert_eq!(layout.register_word_bytes(), RUNTIME_VALUE_CLIF_WORD_BYTES);
        validate_runtime_value_layout(layout).expect("current runtime value layout is supported");

        let candidate = candidate_c_runtime_abi_value_layout();
        validate_runtime_value_layout(candidate)
            .expect("Candidate-C one-word runtime value layout is supported");

        let error = validate_observed_value_layout(ObservedRuntimeValueLayout {
            size_bytes: 16,
            register_words: 1,
            register_word_bytes: 8,
        })
        .expect_err("word count and byte size must agree");
        assert_eq!(
            error,
            JitClifSignatureError::UnsupportedRuntimeValueLayout {
                size_bytes: 16,
                register_words: 1,
                register_word_bytes: 8,
            }
        );
    }

    #[test]
    fn candidate_c_layout_lowers_value_parameters_and_results_to_one_i64() {
        let layout = candidate_c_runtime_abi_value_layout();
        let pointer_type = host_pointer_type().expect("test target has a supported pointer width");
        let signature =
            clif_signature_for_runtime_call_with_layout(runtime_lambda_call_signature(), layout)
                .expect("Candidate-C lambda signature lowers");

        assert_eq!(
            param_types(&signature),
            vec![pointer_type, pointer_type, types::I64]
        );
        assert_eq!(return_types(&signature), vec![types::I64]);
    }

    fn param_types(signature: &Signature) -> Vec<Type> {
        signature
            .params
            .iter()
            .map(|parameter| parameter.value_type)
            .collect()
    }

    fn return_types(signature: &Signature) -> Vec<Type> {
        signature
            .returns
            .iter()
            .map(|parameter| parameter.value_type)
            .collect()
    }
}
