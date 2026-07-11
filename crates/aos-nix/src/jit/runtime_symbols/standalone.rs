//! Address candidates for standalone runtime-FFI helpers.

use super::*;

/// Builds the candidate for the JIT-owned deoptimization trampoline.
///
/// # Errors
///
/// Returns an error if the process-local wrapper address is null.
pub fn nix_jit_deopt_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    candidate(
        "aos_deopt",
        RuntimeHelperRole::Deoptimization,
        ratchet_runtime_ffi::aos_deopt_native_wrapper_address(),
    )
}

/// Builds the candidate for the captured-upvalue reader.
///
/// # Errors
///
/// Returns an error if the process-local wrapper address is null.
pub fn nix_jit_upval_get_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    candidate(
        "aos_upval_get",
        RuntimeHelperRole::EnvironmentAccess,
        ratchet_runtime_ffi::aos_upval_get_native_wrapper_address(),
    )
}

/// Builds the candidate for the primop-dispatch trampoline.
///
/// # Errors
///
/// Returns an error if the process-local wrapper address is null.
pub fn nix_jit_primop_call_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    candidate(
        "aos_primop_call",
        RuntimeHelperRole::PrimopDispatch,
        ratchet_runtime_ffi::aos_primop_call_native_wrapper_address(),
    )
}

fn candidate(
    symbol_name: &'static str,
    role: RuntimeHelperRole,
    address: *mut std::ffi::c_void,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = NonZeroUsize::new(address as usize).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name,
        },
    )?;
    Ok(JitRuntimeSymbolAddressCandidate::new(
        symbol_name.to_owned(),
        RuntimeSymbolKind::Helper(role),
        JitRuntimeSymbolAddress::new(raw),
    ))
}
