//! Runtime-symbol address-candidate resolution and registration preflights.
//!
//! Resolves every frozen runtime helper to its process-local native wrapper
//! (or Rust-callable fallback) address and assembles the registration
//! preflight/plan the engine hands to Cranelift finalization.

use super::*;

/// Builds process-local JIT address candidates from runtime wrapper metadata.
///
/// Covered helper families intentionally use current-process runtime-FFI
/// trap-wrapper addresses, not final exported native ABI targets. Helpers
/// without runtime-FFI wrappers fall back to Rust-callable metadata. The
/// currently covered trap-only helper families are sourced from the unified
/// `ratchet-runtime-ffi` native-wrapper manifest, letting the bridge
/// distinguish native-wrapper address provenance from the remaining
/// native-export blockers. The candidates let integration code exercise JIT
/// registration and relocation plumbing while keeping the actual native call
/// boundary disabled.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be projected into oracle Rust-callable metadata or the unified
/// runtime-FFI native-wrapper manifest. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress`] if a helper
/// binding violates the non-null address invariant before it reaches the JIT
/// registration metadata. Returns
/// [`NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress`]
/// if an `aos_alloc_*`, `aos_env_get`, `aos_apply`, `aos_has_attr`,
/// `aos_select_ic`, `aos_update`, `aos_blackhole_check`, `aos_force`,
/// `aos_force_deep`, or `aos_gc_write_barrier` runtime-FFI wrapper binding
/// violates the non-null address invariant before it reaches the JIT
/// registration metadata.
pub fn nix_jit_runtime_symbol_address_candidate_preflight() -> NixJitPreflightResult {
    let oracle_preflight = runtime_symbol_rust_callable_preflight()?;
    let native_wrappers = runtime_native_wrappers_by_symbol()?;
    let mut address_candidates = Vec::new();
    let mut address_provenance = Vec::new();

    for binding in oracle_preflight.helper_callables().iter().copied() {
        let (candidate, provenance) =
            jit_address_candidate_for_helper_binding(binding, &native_wrappers)?;
        address_candidates.push(candidate);
        address_provenance.push(provenance);
    }

    for candidate in [
        nix_jit_stack_map_enter_address_candidate()?,
        nix_jit_stack_map_exit_address_candidate()?,
    ] {
        address_provenance
            .push(NixJitRuntimeSymbolAddressProvenance::standalone_runtime_ffi_wrapper(&candidate));
        address_candidates.push(candidate);
    }

    Ok(NixJitRuntimeSymbolAddressCandidatePreflight::new(
        address_candidates,
        address_provenance,
        oracle_preflight.missing_bindings().to_vec(),
    ))
}

/// Builds the JIT address candidate for the `aos_string_length` leaf helper.
///
/// `aos_string_length` returns the byte length of an already-forced string. Like
/// [`nix_jit_primop_call_address_candidate`], it is a standalone
/// `ratchet-runtime-ffi` wrapper rather than an oracle-modeled evaluator helper,
/// so it is registered directly from its process-local wrapper address so a
/// compiled `stringLength` inline body importing `aos_string_length` can be
/// finalized. Unlike the primop trampoline it never re-enters the interpreter's
/// builtin dispatch; it performs only the same heap length lookup an ordinary
/// tree-walk `stringLength` does.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress`]
/// if the `aos_string_length` wrapper reports a null process-local address.
pub fn nix_jit_string_length_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let address = ratchet_runtime_ffi::aos_string_length_native_wrapper_address();
    let raw = NonZeroUsize::new(address as usize).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name: "aos_string_length",
        },
    )?;
    Ok(JitRuntimeSymbolAddressCandidate::new(
        "aos_string_length".to_owned(),
        RuntimeSymbolKind::Helper(RuntimeHelperRole::PrimopDispatch),
        JitRuntimeSymbolAddress::new(raw),
    ))
}

/// Builds the JIT address candidate for compiled stack-map entry.
///
/// # Errors
///
/// Returns an error if the wrapper address is null.
pub fn nix_jit_stack_map_enter_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    standalone_runtime_ffi_candidate(
        "aos_jit_stack_map_enter",
        RuntimeHelperRole::SafepointControl,
        ratchet_runtime_ffi::aos_jit_stack_map_enter_native_wrapper_address(),
    )
}

/// Builds the JIT address candidate for compiled stack-map exit.
///
/// # Errors
///
/// Returns an error if the wrapper address is null.
pub fn nix_jit_stack_map_exit_address_candidate()
-> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    standalone_runtime_ffi_candidate(
        "aos_jit_stack_map_exit",
        RuntimeHelperRole::SafepointControl,
        ratchet_runtime_ffi::aos_jit_stack_map_exit_native_wrapper_address(),
    )
}

pub(super) fn standalone_runtime_ffi_candidate(
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

/// Builds JIT runtime-symbol registration readiness from runtime address metadata.
///
/// This top-level integration preflight derives process-local runtime address
/// candidates and feeds them into the JIT runtime-symbol registration preflight.
/// The returned report owns both sides of that handoff for tests and later
/// install planning. It still does not call `JITBuilder::symbol`, export C ABI
/// wrappers, finalize code, dereference helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolRegistrationError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT candidate metadata.
/// Returns [`NixJitRuntimeSymbolRegistrationError::NativeExport`] when oracle
/// native-export readiness metadata cannot be built.
/// Returns [`NixJitRuntimeSymbolRegistrationError::Registration`] when JIT
/// registration metadata cannot be built from the candidate set.
pub fn nix_jit_runtime_symbol_registration_preflight() -> NixJitRuntimeSymbolRegistrationResult {
    let address_candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
    let native_export_preflight = runtime_symbol_native_export_preflight()
        .map_err(|source| NixJitRuntimeSymbolRegistrationError::NativeExport { source })?;
    let address_provenance_gaps =
        address_provenance_gaps(address_candidate_preflight.address_provenance());
    let registration_preflight = jit_runtime_symbol_registration_preflight_with_candidates(
        address_candidate_preflight.address_candidates(),
    )?;
    Ok(NixJitRuntimeSymbolRegistrationPreflight::new(
        address_candidate_preflight,
        native_export_preflight,
        address_provenance_gaps,
        registration_preflight,
    ))
}

/// Builds complete JIT runtime-symbol registration metadata from runtime address metadata.
///
/// This strict gate derives process-local runtime address candidates,
/// builds the JIT registration preflight, carries the oracle native-export
/// readiness preflight, and succeeds only once every stable runtime symbol has
/// declaration/address metadata, native-export metadata, and exported-address
/// provenance. While helper, builtin, native-export, or non-final address
/// provenance gaps remain, the incomplete error carries the owned Nix preflight
/// so callers can inspect the runtime address candidates, native-export
/// blockers, address-provenance gaps, and JIT registration gaps. It still does
/// not call `JITBuilder::symbol`, export C ABI wrappers, finalize code,
/// dereference helper addresses, or call native code.
///
/// # Errors
///
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates`] when
/// runtime helper addresses cannot be projected into JIT candidate metadata.
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::NativeExport`] when
/// oracle native-export readiness metadata cannot be built.
/// Returns [`NixJitRuntimeSymbolRegistrationPlanError::Registration`] when JIT
/// registration metadata cannot be built from the candidate set. Returns
/// [`NixJitRuntimeSymbolRegistrationPlanError::Incomplete`] while any stable
/// runtime-symbol registration, native-export, or address-provenance gate
/// remains incomplete.
pub fn nix_jit_runtime_symbol_registration_plan() -> NixJitRuntimeSymbolRegistrationPlanResult {
    let preflight = nix_jit_runtime_symbol_registration_preflight()?;
    let missing_count = preflight.missing_gate_count();
    if missing_count != 0 {
        return Err(NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
            missing_count,
            preflight,
        });
    }

    let (
        address_candidate_preflight,
        native_export_preflight,
        address_provenance_gaps,
        registration_preflight,
    ) = preflight.into_parts();
    let registration_plan = match registration_preflight.into_registration_plan() {
        Ok(registration_plan) => registration_plan,
        Err(JitRuntimeSymbolRegistrationPlanError::Registration(error)) => {
            return Err(NixJitRuntimeSymbolRegistrationPlanError::Registration(
                error,
            ));
        }
        Err(JitRuntimeSymbolRegistrationPlanError::Incomplete {
            missing_count,
            preflight,
        }) => {
            let missing_count = missing_count
                + native_export_preflight.missing_bindings().len()
                + address_provenance_gaps.len();
            return Err(NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
                missing_count,
                preflight: NixJitRuntimeSymbolRegistrationPreflight::new(
                    address_candidate_preflight,
                    native_export_preflight,
                    address_provenance_gaps,
                    preflight,
                ),
            });
        }
    };

    Ok(NixJitRuntimeSymbolRegistrationPlan::new(
        address_candidate_preflight,
        native_export_preflight,
        registration_plan,
    ))
}

pub(super) fn address_provenance_gaps(
    provenance: &[NixJitRuntimeSymbolAddressProvenance],
) -> Vec<NixJitRuntimeSymbolAddressProvenanceGap> {
    provenance
        .iter()
        .filter_map(NixJitRuntimeSymbolAddressProvenanceGap::from_provenance)
        .collect()
}

pub(super) fn jit_address_candidate_for_helper_binding(
    binding: RuntimeHelperRustCallableBinding,
    native_wrappers: &BTreeMap<&'static str, RuntimeNativeWrapperBinding>,
) -> Result<
    (
        JitRuntimeSymbolAddressCandidate,
        NixJitRuntimeSymbolAddressProvenance,
    ),
    NixJitRuntimeSymbolAddressCandidateError,
> {
    if let Some(native_wrapper) = native_wrappers.get(binding.symbol_name()).copied() {
        let candidate = jit_address_candidate_for_runtime_ffi_native_wrapper(native_wrapper)?;
        let provenance = NixJitRuntimeSymbolAddressProvenance::runtime_ffi_native_wrapper(
            &candidate,
            native_wrapper.remaining_export_blockers(),
        );
        return Ok((candidate, provenance));
    }

    let candidate = jit_address_candidate_for_helper_callable(binding)?;
    let provenance = NixJitRuntimeSymbolAddressProvenance::rust_callable_helper(&candidate);
    Ok((candidate, provenance))
}

pub(super) fn jit_address_candidate_for_helper_callable(
    binding: RuntimeHelperRustCallableBinding,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = helper_callable_address(binding) as usize;
    let address = JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: binding.symbol_name(),
        },
    )?);

    Ok(JitRuntimeSymbolAddressCandidate::new(
        binding.symbol_name().to_owned(),
        RuntimeSymbolKind::Helper(binding.role()),
        address,
    ))
}

pub(super) fn jit_address_candidate_for_runtime_ffi_native_wrapper(
    binding: RuntimeNativeWrapperBinding,
) -> Result<JitRuntimeSymbolAddressCandidate, NixJitRuntimeSymbolAddressCandidateError> {
    let raw = binding.address().as_ptr() as usize;
    let address = JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).ok_or(
        NixJitRuntimeSymbolAddressCandidateError::NullRuntimeFfiNativeWrapperAddress {
            symbol_name: binding.symbol_name(),
        },
    )?);

    Ok(JitRuntimeSymbolAddressCandidate::new(
        binding.symbol_name().to_owned(),
        RuntimeSymbolKind::Helper(binding.role()),
        address,
    ))
}

pub(super) fn helper_callable_address(binding: RuntimeHelperRustCallableBinding) -> *const () {
    match binding {
        RuntimeHelperRustCallableBinding::Allocation(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::CallControl(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::AttrsetAccess(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::EnvironmentAccess(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr(),
        RuntimeHelperRustCallableBinding::WriteBarrier(binding) => binding.address().as_ptr(),
    }
}

pub(super) fn runtime_native_wrappers_by_symbol()
-> Result<BTreeMap<&'static str, RuntimeNativeWrapperBinding>, RuntimeSymbolNameError> {
    Ok(runtime_native_wrapper_bindings()?
        .into_iter()
        .map(|binding| (binding.symbol_name(), binding))
        .collect())
}

#[cfg(test)]
mod provenance_tests {
    use ratchet_oracle::runtime::{
        alloc::RuntimeAllocationNativeExportBlocker, apply::RuntimeApplyNativeExportBlocker,
        attr::RuntimeAttrAccessNativeExportBlocker,
        barrier::RuntimeWriteBarrierNativeExportBlocker, env::RuntimeEnvAccessNativeExportBlocker,
        forcing::RuntimeForcingNativeExportBlocker,
        helpers::RuntimeSymbolNativeExportMissingBinding,
    };

    use super::*;

    #[test]
    fn jit_runtime_symbol_address_provenance_exposes_runtime_ffi_export_blockers() {
        let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let attrs = preflight
            .address_provenance_for_symbol("aos_alloc_attrs")
            .expect("attrs allocation provenance exists");
        let thunk = preflight
            .address_provenance_for_symbol("aos_alloc_thunk")
            .expect("thunk allocation provenance exists");

        assert!(attrs.is_runtime_ffi_native_wrapper());
        assert!(matches!(
            attrs.runtime_ffi_remaining_export_blockers(),
            Some(RuntimeNativeWrapperBlockers::Allocation(blockers))
                if blockers.contains(
                    &RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented
                )
                    && blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented
                    )
                    && blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized
                    )
                    && !blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper
                    )
                    && !blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                    )
        ));
        assert!(matches!(
            thunk.runtime_ffi_remaining_export_blockers(),
            Some(RuntimeNativeWrapperBlockers::Allocation(blockers))
                if blockers.contains(
                    &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                )
                    && !blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper
                    )
        ));

        let registration = nix_jit_runtime_symbol_registration_preflight()
            .expect("Nix JIT registration preflight builds");
        assert!(
            registration
                .native_export_gap_for_symbol("aos_alloc_attrs")
                .is_some_and(
                    |gap| gap
                        .missing_exported_allocation_blockers()
                        .is_some_and(|blockers| blockers.contains(
                            &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper
                        ))
                )
        );
        assert!(
            registration
                .address_provenance_gap_for_symbol("aos_alloc_attrs")
                .is_none()
        );

        let binding = runtime_symbol_rust_callable_preflight()
            .expect("oracle Rust-callable preflight builds")
            .helper_callables()
            .iter()
            .copied()
            .find(|binding| binding.symbol_name() == "aos_env_get")
            .expect("oracle env Rust callable exists");
        let (_, fallback_provenance) =
            jit_address_candidate_for_helper_binding(binding, &BTreeMap::new())
                .expect("fallback Rust-callable candidate builds");

        assert!(fallback_provenance.is_rust_callable_helper());
        assert!(
            fallback_provenance
                .runtime_ffi_remaining_export_blockers()
                .is_none()
        );
    }

    #[test]
    fn jit_runtime_symbol_address_provenance_preserves_family_export_gate_split() {
        let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("JIT address candidate preflight builds");
        let registration_preflight = nix_jit_runtime_symbol_registration_preflight()
            .expect("Nix JIT registration preflight builds");
        let native_wrappers =
            runtime_native_wrapper_bindings().expect("runtime FFI wrapper manifest builds");

        for binding in native_wrappers {
            let provenance = candidate_preflight
                .address_provenance_for_symbol(binding.symbol_name())
                .expect("runtime FFI wrapper provenance exists");
            let blockers = provenance
                .runtime_ffi_remaining_export_blockers()
                .expect("runtime FFI wrapper provenance carries blockers");

            assert_eq!(provenance.kind(), RuntimeSymbolKind::Helper(binding.role()));
            assert_eq!(blockers, binding.remaining_export_blockers());
            assert!(!blockers.contains_final_exported_wrapper_blocker());
            assert!(
                registration_preflight
                    .native_export_gap_for_symbol(binding.symbol_name())
                    .is_some_and(
                        |gap| native_export_gap_contains_final_exported_wrapper_blocker(
                            gap, blockers
                        )
                    )
            );
        }
    }

    fn native_export_gap_contains_final_exported_wrapper_blocker(
        gap: &RuntimeSymbolNativeExportMissingBinding,
        provenance_blockers: RuntimeNativeWrapperBlockers,
    ) -> bool {
        match provenance_blockers {
            RuntimeNativeWrapperBlockers::Allocation(_) => gap
                .missing_exported_allocation_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(
                        &RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
                    )
                }),
            RuntimeNativeWrapperBlockers::CallControl(_) => gap
                .missing_exported_call_control_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(&RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper)
                }),
            RuntimeNativeWrapperBlockers::AttrsetAccess(_) => gap
                .missing_exported_attrset_access_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(
                        &RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper,
                    )
                }),
            RuntimeNativeWrapperBlockers::EnvironmentAccess(_) => gap
                .missing_exported_env_access_blockers()
                .is_some_and(|blockers| {
                    blockers
                        .contains(&RuntimeEnvAccessNativeExportBlocker::MissingFinalExportedWrapper)
                }),
            RuntimeNativeWrapperBlockers::Forcing(_) => gap
                .missing_exported_forcing_blockers()
                .is_some_and(|blockers| {
                    blockers
                        .contains(&RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper)
                }),
            RuntimeNativeWrapperBlockers::WriteBarrier(_) => gap
                .missing_exported_write_barrier_blockers()
                .is_some_and(|blockers| {
                    blockers.contains(
                        &RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper,
                    )
                }),
        }
    }
}
