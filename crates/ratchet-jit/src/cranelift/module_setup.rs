//! Complete JIT module setup: symbol declare/define, ISA construction, and
//! reachable stack-map assembly.

use super::*;

/// Builds a complete JIT module setup for `artifact`.
///
/// This strict gate only succeeds once runtime-symbol readiness is complete.
/// In the current implementation it returns a readiness error because unshaped
/// helper symbols and value-only builtins still have declaration gaps.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::Readiness`] while runtime-symbol
/// declaration gaps remain or if readiness metadata cannot be built. Returns
/// [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot build
/// an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration.
pub fn jit_cranelift_module_setup_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitCraneliftModuleSetup, JitCraneliftModuleSetupError> {
    let readiness = jit_module_readiness_preflight_for_artifact(artifact)?;
    let plan = JitModuleReadinessPlan::from_preflight(readiness)?;
    jit_cranelift_module_setup_for_plan(&plan)
}

/// Builds a complete JIT module setup from a checked readiness plan.
///
/// The returned setup owns a [`JITModule`] whose runtime-symbol imports have
/// been declared but not bound to executable addresses.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift
/// cannot build an ISA for the current host. Returns
/// [`JitCraneliftModuleSetupError::Settings`] if required JIT settings are
/// rejected. Returns [`JitCraneliftModuleSetupError::TargetIsa`] if Cranelift
/// rejects the native ISA configuration. Returns
/// [`JitCraneliftModuleSetupError::DeclareRuntimeSymbol`] if Cranelift rejects
/// an imported runtime-symbol declaration.
pub fn jit_cranelift_module_setup_for_plan(
    plan: &JitModuleReadinessPlan,
) -> Result<JitCraneliftModuleSetup, JitCraneliftModuleSetupError> {
    let (module, imported_symbols) = module_with_imported_symbols(plan.symbol_declarations())?;

    Ok(JitCraneliftModuleSetup::new(
        plan.artifact().clone(),
        imported_symbols,
        module,
    ))
}

pub(crate) fn require_definition_ready_artifact_imports(
    readiness: JitModuleReadinessPreflight,
) -> Result<JitModuleReadinessPreflight, JitCraneliftModuleSetupError> {
    let readiness = require_resolved_artifact_imports(readiness)?;

    let symbol_names = readiness
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name().to_owned())
        .collect::<Vec<_>>();

    if symbol_names.is_empty() {
        Ok(readiness)
    } else {
        Err(
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
                symbol_names,
            },
        )
    }
}

pub(crate) fn require_resolved_artifact_imports(
    readiness: JitModuleReadinessPreflight,
) -> Result<JitModuleReadinessPreflight, JitCraneliftModuleSetupError> {
    if !readiness.artifact_runtime_import_gaps().is_empty() {
        return Err(JitCraneliftModuleSetupError::Readiness(
            JitModuleReadinessError::UnresolvedArtifactRuntimeImports {
                preflight: readiness,
            },
        ));
    }

    Ok(readiness)
}

pub(crate) fn require_registered_artifact_imports(
    readiness: &JitModuleReadinessPreflight,
    registration: &crate::symbols::JitRuntimeSymbolRegistrationPreflight,
) -> Result<(), JitCraneliftModuleSetupError> {
    let missing_symbol_names = readiness
        .artifact_runtime_imports()
        .iter()
        .filter(|artifact_import| {
            registration
                .binding_for_symbol(artifact_import.symbol_name())
                .is_none()
        })
        .map(|artifact_import| artifact_import.symbol_name().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if missing_symbol_names.is_empty() {
        Ok(())
    } else {
        Err(
            JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
                symbol_names: missing_symbol_names,
            },
        )
    }
}

pub(crate) fn module_with_imported_symbols(
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<(JITModule, Vec<JitCraneliftImportedSymbol>), JitCraneliftModuleSetupError> {
    let builder = native_jit_builder()?;
    let mut module = JITModule::new(builder);
    let imported_symbols = declare_imported_symbols(&mut module, declarations)?;

    Ok((module, imported_symbols))
}

pub(crate) fn module_with_registered_symbols(
    bindings: &[JitRuntimeSymbolRegistrationBinding],
) -> Result<(JITModule, Vec<JitCraneliftRegisteredSymbol>), JitCraneliftModuleSetupError> {
    let mut builder = native_jit_builder()?;
    let mut registered_symbols = Vec::with_capacity(bindings.len());

    for binding in bindings {
        builder.symbol(
            binding.symbol_name(),
            ptr::with_exposed_provenance::<u8>(binding.address().as_nonzero_usize().get()),
        );
        registered_symbols.push(JitCraneliftRegisteredSymbol::new(
            binding.symbol_name().to_owned(),
            binding.address(),
        ));
    }

    Ok((JITModule::new(builder), registered_symbols))
}

pub(crate) fn module_with_registered_and_imported_symbols(
    bindings: &[JitRuntimeSymbolRegistrationBinding],
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<
    (
        JITModule,
        Vec<JitCraneliftRegisteredSymbol>,
        Vec<JitCraneliftImportedSymbol>,
    ),
    JitCraneliftModuleSetupError,
> {
    let mut builder = native_jit_builder()?;
    let mut registered_symbols = Vec::with_capacity(bindings.len());

    for binding in bindings {
        builder.symbol(
            binding.symbol_name(),
            ptr::with_exposed_provenance::<u8>(binding.address().as_nonzero_usize().get()),
        );
        registered_symbols.push(JitCraneliftRegisteredSymbol::new(
            binding.symbol_name().to_owned(),
            binding.address(),
        ));
    }

    let mut module = JITModule::new(builder);
    let imported_symbols = declare_imported_symbols(&mut module, declarations)?;

    Ok((module, registered_symbols, imported_symbols))
}

pub(crate) fn declare_imported_symbols(
    module: &mut JITModule,
    declarations: &[JitRuntimeSymbolDeclaration],
) -> Result<Vec<JitCraneliftImportedSymbol>, JitCraneliftModuleSetupError> {
    let mut imported_symbols = Vec::with_capacity(declarations.len());

    for declaration in declarations {
        let func_id = module
            .declare_function(
                declaration.symbol_name(),
                Linkage::Import,
                declaration.signature(),
            )
            .map_err(
                |source| JitCraneliftModuleSetupError::DeclareRuntimeSymbol {
                    symbol_name: declaration.symbol_name().to_owned(),
                    source,
                },
            )?;
        imported_symbols.push(JitCraneliftImportedSymbol::new(
            declaration.symbol_name().to_owned(),
            Linkage::Import,
            func_id,
        ));
    }

    Ok(imported_symbols)
}

pub(crate) fn define_artifact_function(
    module: &mut JITModule,
    artifact: JitClifArtifact,
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let function = artifact.into_function();
    define_artifact_function_body(module, function, symbol_name)
}

pub(crate) fn define_registered_artifact_function(
    module: &mut JITModule,
    artifact: JitClifArtifact,
    imported_symbols: &[JitCraneliftImportedSymbol],
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let mut function = artifact.into_function();
    rewrite_artifact_runtime_imports_for_module(&mut function, imported_symbols);
    define_artifact_function_body(module, function, symbol_name)
}

pub(crate) fn define_artifact_function_body(
    module: &mut JITModule,
    function: Function,
    symbol_name: String,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let func_id = module
        .declare_function(&symbol_name, Linkage::Export, &function.signature)
        .map_err(
            |source| JitCraneliftModuleSetupError::DeclareArtifactFunction {
                symbol_name: symbol_name.clone(),
                source,
            },
        )?;
    let mut context = Context::for_function(function);
    module
        .define_function(func_id, &mut context)
        .map_err(
            |source| JitCraneliftModuleSetupError::DefineArtifactFunction {
                symbol_name: symbol_name.clone(),
                source,
            },
        )?;

    let user_stack_maps = compiled_user_stack_maps(&context);

    Ok(JitCraneliftDefinedFunction::new(
        symbol_name,
        Linkage::Export,
        func_id,
        user_stack_maps,
    ))
}

pub(crate) fn compiled_user_stack_maps(context: &Context) -> Vec<JitCraneliftUserStackMap> {
    context
        .compiled_code()
        .map(|code| {
            code.buffer
                .user_stack_maps()
                .iter()
                .map(|(return_address_offset, call_span, stack_map)| {
                    let mut identity_sp_offset = None;
                    JitCraneliftUserStackMap {
                        return_address_offset: *return_address_offset,
                        call_span: *call_span,
                        entries: stack_map
                            .entries()
                            .filter_map(|(value_type, sp_offset)| {
                                if value_type == cranelift_codegen::ir::types::I32 {
                                    identity_sp_offset = Some(sp_offset);
                                    return None;
                                }
                                Some(JitCraneliftUserStackMapEntry {
                                    value_type,
                                    sp_offset,
                                })
                            })
                            .collect(),
                        identity_sp_offset,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn rewrite_artifact_runtime_imports_for_module(
    function: &mut Function,
    imported_symbols: &[JitCraneliftImportedSymbol],
) {
    let module_func_ids = imported_symbols
        .iter()
        .map(|symbol| (symbol.symbol_name(), symbol.func_id()))
        .collect::<BTreeMap<_, _>>();
    let runtime_import_func_ids = function
        .dfg
        .ext_funcs
        .iter()
        .filter_map(|(func_ref, import)| {
            let ExternalName::User(user_name_ref) = import.name else {
                return None;
            };
            let user_external_name = function.params.user_named_funcs().get(user_name_ref)?;
            let symbol_name = runtime_symbol_name_for_user_external_name(user_external_name)?;
            let func_id = module_func_ids.get(symbol_name)?;
            Some((func_ref, *func_id))
        })
        .collect::<Vec<_>>();

    for (func_ref, func_id) in runtime_import_func_ids {
        let user_name_ref =
            function.declare_imported_user_function(UserExternalName::new(0, func_id.as_u32()));
        if let Some(import) = function.dfg.ext_funcs.get_mut(func_ref) {
            import.name = ExternalName::user(user_name_ref);
        }
    }
}

pub(crate) fn runtime_symbol_name_for_user_external_name(
    user_external_name: &UserExternalName,
) -> Option<&'static str> {
    match (user_external_name.namespace, user_external_name.index) {
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_ENV_GET_FUNCTION_INDEX,
        ) => Some("aos_env_get"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_FORCE_FUNCTION_INDEX,
        ) => Some("aos_force"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_APPLY_FUNCTION_INDEX,
        ) => Some("aos_apply"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_HAS_ATTR_FUNCTION_INDEX,
        ) => Some("aos_has_attr"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_SELECT_IC_FUNCTION_INDEX,
        ) => Some("aos_select_ic"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_UPDATE_FUNCTION_INDEX,
        ) => Some("aos_update"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_DEOPT_FUNCTION_INDEX,
        ) => Some("aos_deopt"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_UPVAL_GET_FUNCTION_INDEX,
        ) => Some("aos_upval_get"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_PRIMOP_CALL_FUNCTION_INDEX,
        ) => Some("aos_primop_call"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_STRING_LENGTH_FUNCTION_INDEX,
        ) => Some("aos_string_length"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_ALLOC_CONS_FUNCTION_INDEX,
        ) => Some("aos_alloc_cons"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX,
        ) => Some("aos_jit_stack_map_enter"),
        (
            crate::lower::AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            crate::lower::AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX,
        ) => Some("aos_jit_stack_map_exit"),
        _ => None,
    }
}

pub(crate) fn finalized_function_pointer(
    module: &JITModule,
    function: &JitCraneliftDefinedFunction,
) -> Result<NonNull<u8>, JitCraneliftModuleSetupError> {
    NonNull::new(module.get_finalized_function(function.func_id()) as *mut u8).ok_or_else(|| {
        JitCraneliftModuleSetupError::FinalizedFunctionPointerNull {
            symbol_name: function.symbol_name().to_owned(),
        }
    })
}

pub(crate) fn tier1_slot_preflight_from_finalization(
    finalization: JitCraneliftArtifactFinalizationPreflight,
    slot: JitTieredCodeSlot,
) -> Result<JitCraneliftTier1SlotPreflight, JitCraneliftModuleSetupError> {
    tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
        .map_err(|(_slot, error)| error)
}

pub(crate) fn tier1_slot_preflight_from_finalization_preserving_slot(
    finalization: JitCraneliftArtifactFinalizationPreflight,
    mut slot: JitTieredCodeSlot,
) -> Result<JitCraneliftTier1SlotPreflight, (JitTieredCodeSlot, JitCraneliftModuleSetupError)> {
    let symbol_name = finalization.finalized_function().symbol_name().to_owned();
    let code_ptr = finalization.finalized_function().compiled_code_ptr();

    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err((
            slot,
            JitCraneliftModuleSetupError::InstallTier1Code {
                symbol_name,
                source,
            },
        ));
    }

    Ok(JitCraneliftTier1SlotPreflight::new(finalization, slot))
}

pub(crate) fn registered_tier1_slot_preflight_from_finalization(
    finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
    slot: JitTieredCodeSlot,
) -> Result<JitCraneliftRegisteredTier1SlotPreflight, JitCraneliftModuleSetupError> {
    registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
        .map_err(|(_slot, error)| error)
}

pub(crate) fn registered_tier1_slot_preflight_from_finalization_preserving_slot(
    finalization: JitCraneliftRegisteredArtifactFinalizationPreflight,
    mut slot: JitTieredCodeSlot,
) -> Result<
    JitCraneliftRegisteredTier1SlotPreflight,
    (JitTieredCodeSlot, JitCraneliftModuleSetupError),
> {
    let symbol_name = finalization.finalized_function().symbol_name().to_owned();
    let code_ptr = finalization.finalized_function().compiled_code_ptr();

    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err((
            slot,
            JitCraneliftModuleSetupError::InstallTier1Code {
                symbol_name,
                source,
            },
        ));
    }

    Ok(JitCraneliftRegisteredTier1SlotPreflight::new(
        finalization,
        slot,
    ))
}

pub(crate) fn module_symbol_name_for_artifact(artifact: &JitModuleArtifactMetadata) -> String {
    let kind = match artifact.kind() {
        JitClifArtifactKind::ThunkBody => "thunk_body",
        JitClifArtifactKind::Tier2LambdaEntry => "tier2_lambda_entry",
        JitClifArtifactKind::Tier2LambdaChainEntry { .. } => "tier2_chain_entry",
        JitClifArtifactKind::Tier2FoldStepI64AccEntry => "tier2_fold_step_i64acc_entry",
    };
    match artifact.source() {
        JitClifArtifactSource::ConstantSmoke => format!("aos.jit.constant_smoke.{kind}"),
        JitClifArtifactSource::IrRoot(root) => {
            format!("aos.jit.ir_root.{}.{kind}", root.as_u32())
        }
    }
}

pub(crate) fn require_supported_native_value_abi() -> Result<(), JitCraneliftNativeCallError> {
    if cfg!(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    )) {
        Ok(())
    } else {
        Err(JitCraneliftNativeCallError::UnsupportedNativeValueAbi {
            message: "native thunk calls require a reviewed by-value Value ABI on this host",
        })
    }
}

pub(super) fn native_jit_builder() -> Result<JITBuilder, JitCraneliftModuleSetupError> {
    Ok(JITBuilder::with_isa(
        cached_native_isa()?,
        cranelift_module::default_libcall_names(),
    ))
}

thread_local! {
    /// Per-thread cache of the finished native [`OwnedTargetIsa`].
    ///
    /// Building a target ISA runs host-CPU feature detection and finishes a fresh
    /// `TargetIsa`, which dominates per-module JIT setup. The ISA is immutable and
    /// shareable (an `Arc`), and every tier-1 module uses the same host ISA and
    /// flags, so it is built once per thread and cloned for each module builder,
    /// amortizing that setup across all promotions.
    static NATIVE_TARGET_ISA: RefCell<Option<OwnedTargetIsa>> = const { RefCell::new(None) };
}

/// Returns the cached native target ISA, building and caching it on first use.
///
/// # Errors
///
/// Returns [`JitCraneliftModuleSetupError::UnsupportedHost`] when Cranelift cannot
/// detect the host CPU, [`JitCraneliftModuleSetupError::Settings`] if a required
/// flag is rejected, and [`JitCraneliftModuleSetupError::TargetIsa`] if the ISA
/// cannot be finished for the host.
fn cached_native_isa() -> Result<OwnedTargetIsa, JitCraneliftModuleSetupError> {
    NATIVE_TARGET_ISA.with(|cell| {
        if let Some(isa) = cell.borrow().as_ref() {
            return Ok(isa.clone());
        }
        let mut flag_builder = settings::builder();
        flag_builder.set("use_colocated_libcalls", "false")?;
        flag_builder.set("is_pic", "false")?;
        let isa_builder = cranelift_native::builder()
            .map_err(|message| JitCraneliftModuleSetupError::UnsupportedHost { message })?;
        let isa = isa_builder.finish(settings::Flags::new(flag_builder))?;
        *cell.borrow_mut() = Some(isa.clone());
        Ok(isa)
    })
}
