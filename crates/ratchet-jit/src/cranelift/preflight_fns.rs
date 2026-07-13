//! Artifact declaration/definition/finalization preflight builders and the
//! no-import / registered native thunk-call entrypoints.

use super::*;

/// Builds a real JIT module and declares shape-known runtime symbol imports.
///
/// The returned preflight owns a [`JITModule`] with callable builtin and
/// core-owned allocation, call-control apply, environment-access,
/// write-barrier, and force/deep-force helper imports declared using
/// `Linkage::Import`. Unshaped helpers and value-only builtins remain explicit
/// gaps. No runtime symbol addresses are registered and no CLIF functions are
/// defined, finalized, or called.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if runtime-symbol
/// readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration.
pub fn jit_cranelift_module_declaration_preflight_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitCraneliftModuleDeclarationPreflight, JitCraneliftModuleSetupError> {
    let readiness = jit_module_readiness_preflight_for_artifact(artifact)?;
    let (module, imported_symbols) = module_with_imported_symbols(readiness.symbol_declarations())?;

    Ok(JitCraneliftModuleDeclarationPreflight::new(
        readiness.artifact().clone(),
        imported_symbols,
        readiness.symbol_gaps().to_vec(),
        module,
    ))
}

/// Builds a JIT module from a builder with explicit runtime symbols registered.
///
/// The returned preflight calls [`JITBuilder::symbol`] for every runtime symbol
/// that has both CLIF declaration metadata and explicit native-address candidate
/// metadata. Missing declarations, missing addresses, kind mismatches, duplicate
/// candidates, and unknown candidates remain explicit gaps or errors from the
/// registration metadata layer. The resulting module is not given imported
/// declarations, no CLIF body is defined or finalized, and no registered address
/// is dereferenced or called.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`] if
/// runtime-symbol registration metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration.
pub fn jit_cranelift_symbol_registration_preflight_with_candidates(
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftSymbolRegistrationPreflight, JitCraneliftModuleSetupError> {
    let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    let (module, registered_symbols) = module_with_registered_symbols(registration.bindings())?;

    Ok(JitCraneliftSymbolRegistrationPreflight::new(
        registered_symbols,
        registration.gaps().to_vec(),
        module,
    ))
}

/// Registers explicit runtime symbols and defines one verified CLIF artifact body.
///
/// The returned preflight calls [`JITBuilder::symbol`] for every supplied
/// native-address candidate that matches CLIF declaration metadata, declares
/// shape-known runtime imports in the same module, rewrites artifact runtime
/// imports to Cranelift module-local function references, and passes the artifact
/// body to Cranelift's definition API. It does not finalize definitions,
/// dereference registered addresses, expose a code pointer, or call native code.
/// Stable runtime symbols outside the artifact's import set may remain
/// registration gaps.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if artifact readiness
/// metadata cannot be built or has unresolved runtime imports. Returns
/// [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`] if
/// runtime-symbol registration metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact imports a runtime symbol without matching native-address
/// registration metadata. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition.
pub fn jit_cranelift_registered_artifact_definition_preflight_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredArtifactDefinitionPreflight, JitCraneliftModuleSetupError> {
    let readiness =
        require_resolved_artifact_imports(jit_module_readiness_preflight_for_artifact(&artifact)?)?;
    let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    require_registered_artifact_imports(&readiness, &registration)?;

    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let artifact_runtime_imports = readiness.artifact_runtime_imports().to_vec();
    let registration_gaps = registration.gaps().to_vec();
    let (mut module, registered_symbols, imported_symbols) =
        module_with_registered_and_imported_symbols(
            registration.bindings(),
            readiness.symbol_declarations(),
        )?;
    let defined_function =
        define_registered_artifact_function(&mut module, artifact, &imported_symbols, symbol_name)?;

    Ok(JitCraneliftRegisteredArtifactDefinitionPreflight::new(
        artifact_metadata,
        defined_function,
        imported_symbols,
        registered_symbols,
        artifact_runtime_imports,
        registration_gaps,
        module,
    ))
}

/// Registers explicit runtime symbols, defines one artifact body, and finalizes it.
///
/// The returned preflight composes the registered-symbol artifact-definition path
/// with [`JITModule::finalize_definitions`], returning a non-null opaque code
/// pointer for the finalized artifact body. Registered addresses may be used by
/// Cranelift relocation during finalization, but this path does not dereference
/// those addresses directly, cast the finalized code pointer, install tier
/// metadata, or call native code. Stable runtime symbols outside the artifact's
/// import set may remain registration gaps.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if artifact readiness
/// metadata cannot be built or has unresolved runtime imports. Returns
/// [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`] if
/// runtime-symbol registration metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact imports a runtime symbol without matching native-address
/// registration metadata. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition. Returns
/// [`JitCraneliftModuleSetupError::FinalizeDefinitions`] if Cranelift cannot
/// finalize the module definitions. Returns
/// [`JitCraneliftModuleSetupError::FinalizedFunctionPointerNull`] if Cranelift
/// reports a null code pointer after successful finalization.
///
/// # Panics
///
/// Panics if Cranelift reports successful artifact definition and module
/// finalization but then fails its own invariant for looking up the finalized
/// function by [`FuncId`].
pub fn jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredArtifactFinalizationPreflight, JitCraneliftModuleSetupError> {
    let readiness =
        require_resolved_artifact_imports(jit_module_readiness_preflight_for_artifact(&artifact)?)?;
    let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
    require_registered_artifact_imports(&readiness, &registration)?;

    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let artifact_runtime_imports = readiness.artifact_runtime_imports().to_vec();
    let registration_gaps = registration.gaps().to_vec();
    let (mut module, registered_symbols, imported_symbols) =
        module_with_registered_and_imported_symbols(
            registration.bindings(),
            readiness.symbol_declarations(),
        )?;
    let defined_function =
        define_registered_artifact_function(&mut module, artifact, &imported_symbols, symbol_name)?;

    module.finalize_definitions().map_err(|source| {
        JitCraneliftModuleSetupError::FinalizeDefinitions {
            symbol_name: defined_function.symbol_name().to_owned(),
            source,
        }
    })?;
    let code_ptr = finalized_function_pointer(&module, &defined_function)?;
    let finalized_function = JitCraneliftFinalizedFunction::new(defined_function, code_ptr);

    Ok(JitCraneliftRegisteredArtifactFinalizationPreflight::new(
        artifact_metadata,
        finalized_function,
        imported_symbols,
        registered_symbols,
        artifact_runtime_imports,
        registration_gaps,
        module,
    ))
}

/// Builds a real JIT module and defines one verified CLIF artifact body.
///
/// The returned preflight owns a [`JITModule`] with callable builtin imports
/// declared, plus one artifact body declared as an exported function and passed
/// to Cranelift's definition API. Unshaped helper and value-only builtin gaps
/// are preserved. Artifacts with runtime imports are rejected by this
/// unregistered path and must use the registered-symbol definition path. A
/// successful definition lets Cranelift compile the body and allocate JIT code
/// memory inside the private module. The module is not finalized, no code
/// pointer is returned, and no native code is called.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if runtime-symbol
/// readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact body imports runtime helpers that the current path cannot
/// register. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition.
pub fn jit_cranelift_artifact_definition_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftArtifactDefinitionPreflight, JitCraneliftModuleSetupError> {
    let readiness = require_definition_ready_artifact_imports(
        jit_module_readiness_preflight_for_artifact(&artifact)?,
    )?;
    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let symbol_gaps = readiness.symbol_gaps().to_vec();
    let (mut module, imported_symbols) =
        module_with_imported_symbols(readiness.symbol_declarations())?;
    let defined_function = define_artifact_function(&mut module, artifact, symbol_name)?;

    Ok(JitCraneliftArtifactDefinitionPreflight::new(
        artifact_metadata,
        defined_function,
        imported_symbols,
        symbol_gaps,
        module,
    ))
}

/// Builds a real JIT module, defines one verified CLIF artifact, and finalizes it.
///
/// The returned preflight owns a [`JITModule`] with callable builtin imports,
/// one artifact body declared as an exported function, and finalized executable
/// memory for that body. The finalized code pointer is exposed only as opaque
/// metadata for later unsafe call-boundary work. This does not cast the code
/// pointer to a function pointer, call native code, or lower generic IR.
/// This unregistered API rejects call-bearing artifacts; those artifacts must
/// use the registered-symbol finalization path. Full native-call integration
/// still requires real exported wrappers and matching address registration for
/// every emitted runtime call.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] if runtime-symbol
/// readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration. Returns
/// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
/// when the artifact body imports runtime helpers that the current path cannot
/// register. Returns
/// [`JitCraneliftModuleSetupError::DeclareArtifactFunction`] if Cranelift
/// rejects the artifact function declaration. Returns
/// [`JitCraneliftModuleSetupError::DefineArtifactFunction`] if Cranelift rejects
/// the artifact function definition. Returns
/// [`JitCraneliftModuleSetupError::FinalizeDefinitions`] if Cranelift cannot
/// finalize the module definitions. Returns
/// [`JitCraneliftModuleSetupError::FinalizedFunctionPointerNull`] if Cranelift
/// reports a null code pointer after successful finalization.
///
/// # Panics
///
/// Panics if Cranelift reports successful artifact definition and module
/// finalization but then fails its own invariant for looking up the finalized
/// function by [`FuncId`].
pub fn jit_cranelift_artifact_finalization_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftArtifactFinalizationPreflight, JitCraneliftModuleSetupError> {
    let readiness = require_definition_ready_artifact_imports(
        jit_module_readiness_preflight_for_artifact(&artifact)?,
    )?;
    let symbol_name = module_symbol_name_for_artifact(readiness.artifact());
    let artifact_metadata = readiness.artifact().clone();
    let symbol_gaps = readiness.symbol_gaps().to_vec();
    let (mut module, imported_symbols) =
        module_with_imported_symbols(readiness.symbol_declarations())?;
    let defined_function = define_artifact_function(&mut module, artifact, symbol_name)?;

    module.finalize_definitions().map_err(|source| {
        JitCraneliftModuleSetupError::FinalizeDefinitions {
            symbol_name: defined_function.symbol_name().to_owned(),
            source,
        }
    })?;
    let code_ptr = finalized_function_pointer(&module, &defined_function)?;
    let finalized_function = JitCraneliftFinalizedFunction::new(defined_function, code_ptr);

    Ok(JitCraneliftArtifactFinalizationPreflight::new(
        artifact_metadata,
        finalized_function,
        imported_symbols,
        symbol_gaps,
        module,
    ))
}

/// Finalizes one thunk artifact and calls it through the native thunk ABI.
///
/// This is the first bounded native-call path for the Cranelift tier. It is
/// intended for currently supported no-import thunk artifacts, such as constant
/// smoke bodies and literal Core-IR roots. The call uses null runtime-context
/// and environment-frame pointers because those lowerers ignore both entry
/// parameters. The returned invocation owns the finalization preflight so the
/// backing [`JITModule`] remains alive for inspection after the call.
///
/// This function does not publish the code pointer into evaluator thunk state,
/// perform an atomic thunk-state transition, call registered runtime helpers, or
/// support artifacts that import runtime symbols.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::FinalizeArtifact`] when the artifact
/// cannot be finalized, including the current registered-symbol requirement for
/// runtime-importing artifacts. Returns
/// [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the current
/// host has no reviewed by-value [`Value`] ABI parity with the two-word CLIF
/// lowering. Returns
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the finalized
/// artifact metadata is not a thunk body. Returns
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the native thunk
/// returns a valid-tag [`Value`] whose payload bits violate the runtime layout.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_artifact_finalization_preflight_for_artifact`].
pub fn jit_cranelift_native_thunk_call_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftNativeThunkInvocation, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    let finalization = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)
        .map_err(|source| JitCraneliftNativeCallError::FinalizeArtifact { source })?;

    if finalization.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: finalization.artifact().kind(),
        });
    }
    require_artifact_value_abi(finalization.artifact(), JitValueAbi::Active)?;

    let thunk_entry = thunk_entry_from_finalized_code(finalization.finalized_function().code_ptr());
    // SAFETY: The artifact was produced by this crate's thunk-body lowerers,
    // verified with the frozen thunk CLIF signature, finalized by Cranelift,
    // and kept alive by `finalization`. The current no-import lowerers used by
    // this path do not dereference the runtime or environment pointers.
    let value = unsafe { thunk_entry(ptr::null_mut(), ptr::null_mut()) };
    value
        .validate_payload()
        .map_err(|source| JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: finalization.finalized_function().symbol_name().to_owned(),
            value,
            source,
        })?;

    Ok(JitCraneliftNativeThunkInvocation::new(finalization, value))
}

/// Finalizes one registered thunk artifact and calls it through the native thunk ABI.
///
/// This is the bounded native-call path for artifacts that import runtime
/// helpers, such as the current local environment-slot and forced environment
/// precursors. It composes explicit native-address candidates with the
/// registered finalization path, then calls the finalized thunk entry while
/// keeping the backing [`JITModule`] alive in the returned invocation.
///
/// This function does not publish the code pointer into evaluator thunk state,
/// perform an atomic thunk-state transition, or validate that supplied helper
/// addresses came from exported AOS runtime wrappers. It only checks that
/// candidate symbol names and kinds match JIT declaration metadata before those
/// addresses are registered with Cranelift.
///
/// # Safety
///
/// Every native-address candidate that can be called by `artifact` must point to
/// a live function with the exact frozen `extern "C"` ABI for its runtime
/// symbol, and it must remain valid until the returned invocation is dropped.
/// `rt` and `env` must be valid for the compiled thunk body and for every helper
/// candidate the body can call. Candidate functions must not unwind across the C
/// ABI boundary. Every compiled body and candidate return path must produce a
/// valid [`Value`] tag; payload-layout violations can be reported as
/// [`JitCraneliftNativeCallError::InvalidReturnValue`], but invalid enum
/// discriminants cannot be materialized safely after crossing back into Rust.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::FinalizeArtifact`] when the artifact
/// cannot be finalized through the registered-symbol path, including missing or
/// wrong-kind candidates for artifact imports. Returns
/// [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the current
/// host has no reviewed by-value [`Value`] ABI parity with the two-word CLIF
/// lowering. Returns
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the finalized
/// artifact metadata is not a thunk body. Returns
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the native thunk
/// returns a valid-tag [`Value`] whose payload bits violate the runtime layout.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
pub unsafe fn jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<JitCraneliftRegisteredNativeThunkInvocation, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    let finalization = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact, candidates,
    )
    .map_err(|source| JitCraneliftNativeCallError::FinalizeArtifact { source })?;

    if finalization.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: finalization.artifact().kind(),
        });
    }
    require_artifact_value_abi(finalization.artifact(), JitValueAbi::Active)?;

    let thunk_entry = thunk_entry_from_finalized_code(finalization.finalized_function().code_ptr());
    // SAFETY: The caller guarantees that registered helper candidates and the
    // runtime/environment pointers satisfy the frozen native ABI for this
    // artifact. The artifact body was produced by this crate's thunk lowerers,
    // verified with the frozen thunk CLIF signature, finalized by Cranelift, and
    // kept alive by `finalization`.
    let value = unsafe { thunk_entry(rt, env) };
    value
        .validate_payload()
        .map_err(|source| JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: finalization.finalized_function().symbol_name().to_owned(),
            value,
            source,
        })?;

    Ok(JitCraneliftRegisteredNativeThunkInvocation::new(
        finalization,
        value,
    ))
}

/// Calls an already-finalized thunk-body artifact and returns its runtime value.
///
/// Unlike
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`],
/// this entrypoint does not finalize or install anything: it borrows a
/// finalization preflight that a caller has already produced (and continues to
/// own for the duration of the call), casts its finalized code pointer to the
/// frozen thunk ABI, invokes it, and returns the validated [`Value`]. It exists
/// so the tier-1 publish path can dispatch a promoted artifact whose finalized
/// code pointer is pinned by an out-of-band owner without re-running module
/// setup on every call.
///
/// The borrowed `finalization` keeps its encapsulated `JITModule` — and hence
/// the finalized code memory — alive across the call. Because this crate never
/// relocates finalized code, the code pointer read here is identical to the one
/// the caller finalized.
///
/// # Safety
///
/// The finalized artifact and every native-address candidate registered into its
/// module during finalization must point to live functions with the exact frozen
/// `extern "C"` ABI for their runtime symbols, and `finalization` must not be
/// dropped until this call returns. `rt` and `env` must be valid for the
/// compiled thunk body and for every helper the body can call. Candidate
/// functions must not unwind across the C ABI boundary. The compiled body must
/// produce a valid [`Value`] tag; payload-layout violations are reported as
/// [`JitCraneliftNativeCallError::InvalidReturnValue`], but an invalid enum
/// discriminant cannot be materialized safely after crossing back into Rust.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the
/// current host has no reviewed by-value [`Value`] ABI parity with the two-word
/// CLIF lowering. Returns
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the finalized
/// artifact metadata is not a thunk body. Returns
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the native thunk
/// returns a valid-tag [`Value`] whose payload bits violate the runtime layout.
pub unsafe fn jit_cranelift_call_finalized_thunk_entry(
    finalization: &JitCraneliftRegisteredArtifactFinalizationPreflight,
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<Value, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    if finalization.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: finalization.artifact().kind(),
        });
    }
    require_artifact_value_abi(finalization.artifact(), JitValueAbi::Active)?;

    let thunk_entry = thunk_entry_from_finalized_code(finalization.finalized_function().code_ptr());
    // SAFETY: The caller guarantees that the borrowed finalization's registered
    // helper candidates and the runtime/environment pointers satisfy the frozen
    // native ABI for this artifact, and that `finalization` outlives this call.
    // The artifact body was produced by this crate's thunk lowerers, verified
    // with the frozen thunk CLIF signature, finalized by Cranelift, and kept
    // alive by `finalization`'s encapsulated module.
    let dispatched = unsafe { thunk_entry(rt, env) };
    dispatched.validate_payload().map_err(|source| {
        JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: finalization.finalized_function().symbol_name().to_owned(),
            value: dispatched,
            source,
        }
    })?;

    Ok(dispatched)
}

