//! Tier-2 lambda define/finalize path and native call boundary.
//!
//! A tier-2 lowering (see [`crate::lower::lambda_rec`]) produces *two* CLIF
//! functions: a module-local recursive `inner` body and an exported `entry`
//! adapter with the frozen lambda-call ABI. The per-body
//! [`JitModuleContext::define_and_finalize`](super::JitModuleContext) path
//! defines exactly one function per artifact, so this module owns the paired
//! define: it declares `inner` first (module-local linkage), rewrites the
//! self-recursive references in `inner` and the `inner` reference in `entry`
//! to the assigned `FuncId`, defines both, and finalizes the shared module so
//! the entry's code pointer becomes callable.
//!
//! It also owns the one new unsafe boundary tier-2 adds: casting the entry's
//! finalized code pointer to the frozen [`JitLambdaFn`] ABI and calling it
//! with the runtime context, environment, and the applied argument value.
//! The token-counted allowlist in [`crate::safety`] pins both the transmute
//! and the call to single reviewed lines in this file.

use std::mem;
use std::ptr::NonNull;

use cranelift_codegen::ir::{ExternalName, Function, UserExternalName};
use cranelift_jit::JITModule;
use cranelift_module::{Linkage, Module};
use ratchet_core::IrId;
use ratchet_value::value::Value;

use crate::abi::{
    JitEnvFramePtr, JitFoldStepI64AccFn, JitLambdaArgvFn, JitLambdaFn, JitRuntimeContextPtr,
};
use crate::artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource};
use crate::lower::{
    AOS_TIER2_LOCAL_FUNCTION_NAMESPACE, JitTier2ChainLowering, JitTier2LambdaLowering,
};
use crate::module::JitModuleArtifactMetadata;
use crate::symbols::jit_runtime_symbol_declaration_preflight;
use crate::tier::JitTier;

use super::{
    JitCraneliftDefinedFunction, JitCraneliftFinalizedFunction, JitCraneliftImportedSymbol,
    JitCraneliftModuleSetupError, JitCraneliftNativeCallError, JitModuleContext,
    JitModuleContextFinalizedBody, declare_imported_symbols, define_artifact_function_body,
    finalized_function_pointer, module_symbol_name_for_artifact,
    require_supported_native_value_abi, runtime_symbol_name_for_user_external_name,
};

impl JitModuleContext {
    /// Defines and finalizes one tier-2 lambda lowering into the shared module.
    ///
    /// Declares the runtime helper imports the body needs (`aos_force`,
    /// `aos_deopt`) against the module's registered candidates, declares the
    /// recursive `inner` body with module-local linkage, rewrites the tier-2
    /// local references in both functions to `inner`'s assigned `FuncId`,
    /// defines both functions, and finalizes the module. The returned body
    /// carries the *entry* function's code pointer and
    /// [`JitClifArtifactKind::Tier2LambdaEntry`] metadata; `inner` is reachable
    /// only through the entry (and through itself).
    ///
    /// # Errors
    ///
    /// Returns
    /// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
    /// when a required helper has no registered address candidate in this
    /// context, [`JitCraneliftModuleSetupError::RuntimeSymbolRegistration`]
    /// when the stable declaration manifest cannot be built, and the
    /// declaration, definition, finalization, and null-pointer errors of the
    /// shared per-body path.
    pub fn define_and_finalize_tier2_lambda(
        &self,
        lowering: JitTier2LambdaLowering,
    ) -> Result<JitModuleContextFinalizedBody, JitCraneliftModuleSetupError> {
        let source = lowering.source();
        let (entry, inner) = lowering.into_functions();
        self.define_and_finalize_tier2_pair(
            JitClifArtifactKind::Tier2LambdaEntry,
            source,
            entry,
            inner,
        )
    }

    /// Defines and finalizes one tier-2 fused chain lowering into the module.
    ///
    /// The chain analogue of
    /// [`define_and_finalize_tier2_lambda`](Self::define_and_finalize_tier2_lambda):
    /// identical paired-define protocol, with the entry carrying
    /// [`JitClifArtifactKind::Tier2LambdaChainEntry`] metadata (including the
    /// chain arity the native boundary re-checks against the caller's `argv`
    /// run).
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`define_and_finalize_tier2_lambda`](Self::define_and_finalize_tier2_lambda).
    pub fn define_and_finalize_tier2_chain(
        &self,
        lowering: JitTier2ChainLowering,
    ) -> Result<JitModuleContextFinalizedBody, JitCraneliftModuleSetupError> {
        let source = lowering.source();
        let arity = lowering.arity().min(u32::from(u8::MAX)) as u8;
        let (entry, inner) = lowering.into_functions();
        self.define_and_finalize_tier2_pair(
            JitClifArtifactKind::Tier2LambdaChainEntry { arity },
            source,
            entry,
            inner,
        )
    }

    /// Defines and finalizes one tier-2 fold-step (decoded-`i64`-accumulator)
    /// lowering into the module.
    ///
    /// The fold-step analogue of
    /// [`define_and_finalize_tier2_chain`](Self::define_and_finalize_tier2_chain):
    /// identical paired-define protocol, with the entry carrying
    /// [`JitClifArtifactKind::Tier2FoldStepI64AccEntry`] metadata so the native
    /// fold-loop boundary can reject an entry lowered against the wrong ABI.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`define_and_finalize_tier2_chain`](Self::define_and_finalize_tier2_chain).
    pub fn define_and_finalize_tier2_fold_step_i64acc(
        &self,
        lowering: JitTier2ChainLowering,
    ) -> Result<JitModuleContextFinalizedBody, JitCraneliftModuleSetupError> {
        let source = lowering.source();
        let (entry, inner) = lowering.into_functions();
        self.define_and_finalize_tier2_pair(
            JitClifArtifactKind::Tier2FoldStepI64AccEntry,
            source,
            entry,
            inner,
        )
    }

    /// Defines and finalizes one tier-2 entry/inner function pair.
    ///
    /// Shared worker for the lambda and chain define paths; see
    /// [`define_and_finalize_tier2_lambda`](Self::define_and_finalize_tier2_lambda)
    /// for the protocol.
    fn define_and_finalize_tier2_pair(
        &self,
        kind: JitClifArtifactKind,
        source: IrId,
        entry: Function,
        inner: Function,
    ) -> Result<JitModuleContextFinalizedBody, JitCraneliftModuleSetupError> {
        let inner_ctx = &mut *self.inner.borrow_mut();

        // The tier-2 grammar imports at most these helpers (`aos_upval_get`
        // only when the body reads its environment); require their registered
        // addresses up front so finalization cannot dangle.
        let required = [
            "aos_force",
            "aos_deopt",
            "aos_upval_get",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
        ];
        let missing: Vec<String> = required
            .iter()
            .filter(|name| {
                !inner_ctx
                    .registration
                    .bindings()
                    .iter()
                    .any(|binding| binding.symbol_name() == **name)
            })
            .map(|name| (*name).to_owned())
            .collect();
        if !missing.is_empty() {
            return Err(
                JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration {
                    symbol_names: missing,
                },
            );
        }
        let declaration_preflight =
            jit_runtime_symbol_declaration_preflight().map_err(|error| {
                JitCraneliftModuleSetupError::RuntimeSymbolRegistration(
                    crate::symbols::JitRuntimeSymbolRegistrationError::Declaration(error),
                )
            })?;
        let declarations: Vec<_> = declaration_preflight
            .declarations()
            .iter()
            .filter(|declaration| required.contains(&declaration.symbol_name()))
            .cloned()
            .collect();
        let imported_symbols = declare_imported_symbols(&mut inner_ctx.module, &declarations)?;

        // Wrap the entry in artifact metadata for the boundary kind check and
        // the export symbol name.
        let entry_artifact = JitClifArtifact::new(
            JitTier::Tier1Baseline,
            kind,
            JitClifArtifactSource::IrRoot(source),
            entry,
        );
        let artifact_metadata = JitModuleArtifactMetadata::from_artifact(&entry_artifact);
        let base_symbol_name = module_symbol_name_for_artifact(&artifact_metadata);
        inner_ctx.define_counter = inner_ctx.define_counter.saturating_add(1);
        let entry_symbol_name = format!("{base_symbol_name}.{}", inner_ctx.define_counter);
        let inner_symbol_name = format!("{entry_symbol_name}.inner");

        // Declare the recursive body first so both functions can reference its
        // `FuncId`, then rewrite and define each function.
        let mut inner_function = inner;
        let inner_id = inner_ctx
            .module
            .declare_function(
                &inner_symbol_name,
                Linkage::Local,
                &inner_function.signature,
            )
            .map_err(
                |source| JitCraneliftModuleSetupError::DeclareArtifactFunction {
                    symbol_name: inner_symbol_name.clone(),
                    source,
                },
            )?;
        rewrite_tier2_function_references(&mut inner_function, &imported_symbols, inner_id);
        let defined_inner = define_declared_function(
            &mut inner_ctx.module,
            inner_function,
            inner_symbol_name,
            inner_id,
        )?;
        let inner_user_stack_maps = defined_inner.user_stack_maps().to_vec();

        let mut entry_function = entry_artifact.into_function();
        rewrite_tier2_function_references(&mut entry_function, &imported_symbols, inner_id);
        let defined_entry = define_artifact_function_body(
            &mut inner_ctx.module,
            entry_function,
            entry_symbol_name,
        )?;

        inner_ctx.module.finalize_definitions().map_err(|source| {
            JitCraneliftModuleSetupError::FinalizeDefinitions {
                symbol_name: defined_entry.symbol_name().to_owned(),
                source,
            }
        })?;
        let code_ptr = finalized_function_pointer(&inner_ctx.module, &defined_entry)?;
        let finalized_function = JitCraneliftFinalizedFunction::new_with_runtime_user_stack_maps(
            defined_entry,
            code_ptr,
            inner_user_stack_maps,
        );

        Ok(JitModuleContextFinalizedBody {
            artifact: artifact_metadata,
            finalized_function,
        })
    }
}

/// Defines a function whose `FuncId` was already declared by the caller.
///
/// Mirrors the shared declare-and-define helper but skips the declaration,
/// which the tier-2 path performs early so the recursive body can reference
/// its own id.
fn define_declared_function(
    module: &mut JITModule,
    function: Function,
    symbol_name: String,
    func_id: cranelift_module::FuncId,
) -> Result<JitCraneliftDefinedFunction, JitCraneliftModuleSetupError> {
    let mut context = cranelift_codegen::Context::for_function(function);
    module
        .define_function(func_id, &mut context)
        .map_err(
            |source| JitCraneliftModuleSetupError::DefineArtifactFunction {
                symbol_name: symbol_name.clone(),
                source,
            },
        )?;
    let user_stack_maps = super::compiled_user_stack_maps(&context);
    Ok(JitCraneliftDefinedFunction::new(
        symbol_name,
        Linkage::Local,
        func_id,
        user_stack_maps,
    ))
}

/// Rewrites a tier-2 function's external references onto module `FuncId`s.
///
/// Runtime helper imports (the `aos_*` namespace) are rewritten exactly like
/// the shared per-body path; references in the tier-2 local namespace (the
/// recursive self-call in `inner`, the `inner` call in `entry`) are rewritten
/// to `inner_id`.
fn rewrite_tier2_function_references(
    function: &mut Function,
    imported_symbols: &[JitCraneliftImportedSymbol],
    inner_id: cranelift_module::FuncId,
) {
    let rewrites: Vec<_> = function
        .dfg
        .ext_funcs
        .iter()
        .filter_map(|(func_ref, import)| {
            let ExternalName::User(user_name_ref) = import.name else {
                return None;
            };
            let user_external_name = function.params.user_named_funcs().get(user_name_ref)?;
            if user_external_name.namespace == AOS_TIER2_LOCAL_FUNCTION_NAMESPACE {
                return Some((func_ref, inner_id));
            }
            let symbol_name = runtime_symbol_name_for_user_external_name(user_external_name)?;
            let func_id = imported_symbols
                .iter()
                .find(|symbol| symbol.symbol_name() == symbol_name)
                .map(JitCraneliftImportedSymbol::func_id)?;
            Some((func_ref, func_id))
        })
        .collect();

    for (func_ref, func_id) in rewrites {
        let user_name_ref =
            function.declare_imported_user_function(UserExternalName::new(0, func_id.as_u32()));
        if let Some(import) = function.dfg.ext_funcs.get_mut(func_ref) {
            import.name = ExternalName::user(user_name_ref);
        }
    }
}

/// Calls a shared-context finalized tier-2 lambda entry with one argument.
///
/// This mirrors
/// [`jit_cranelift_call_context_finalized_thunk_entry`](super::jit_cranelift_call_context_finalized_thunk_entry)
/// for the frozen lambda-call ABI: it casts the entry's finalized code pointer
/// to [`JitLambdaFn`], invokes it with `rt`, `env`, and the applied
/// `argument`, and validates the returned [`Value`]. A deopting execution
/// returns a null value with the deopt trap recorded in the armed runtime trap
/// scope; the safe wrapper reads the scope to distinguish it.
///
/// # Safety
///
/// The [`JitModuleContext`] that finalized `body` — or a keep-alive handle
/// cloned from it — must stay alive until this call returns, and every
/// native-address candidate registered into that context must point to a live
/// function with the exact frozen `extern "C"` ABI for its runtime symbol.
/// `rt` must be a pinned runtime context over a live evaluator, `env` must
/// point to caller-owned environment storage valid for the call, `argument`
/// must be a valid runtime value owned by the caller's evaluator, and a
/// runtime trap scope must be armed so a forcing error transfers as a trap
/// instead of aborting.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the
/// host has no reviewed by-value [`Value`] ABI,
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the body is
/// not a tier-2 lambda entry, and
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the body returns a
/// valid-tag [`Value`] whose payload bits violate the runtime layout.
pub unsafe fn jit_cranelift_call_context_finalized_lambda_entry(
    body: &JitModuleContextFinalizedBody,
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
    argument: Value,
) -> Result<Value, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    if body.artifact().kind() != JitClifArtifactKind::Tier2LambdaEntry {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: body.artifact().kind(),
        });
    }

    let lambda_entry = lambda_entry_from_finalized_code(body.finalized_function().code_ptr());
    // SAFETY: The caller keeps the finalizing `JitModuleContext` (or a cloned
    // keep-alive handle) alive across this call, so the shared module's code
    // memory and every registered frozen-ABI candidate remain live. The body was
    // produced by the tier-2 lambda lowerer, verified with the frozen lambda
    // CLIF signature, and finalized by Cranelift; `rt`, `env`, and `argument`
    // satisfy the frozen native ABI and its entry translates the internal deopt
    // sentinel to a valid null before returning.
    let lambda_dispatched = unsafe { lambda_entry(rt, env, argument) };
    lambda_dispatched.validate_payload().map_err(|source| {
        JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: body.finalized_function().symbol_name().to_owned(),
            value: lambda_dispatched,
            source,
        }
    })?;

    Ok(lambda_dispatched)
}

/// Casts a finalized tier-2 entry code pointer to the frozen lambda ABI.
fn lambda_entry_from_finalized_code(code_ptr: NonNull<u8>) -> JitLambdaFn {
    // SAFETY: Cranelift returned this pointer for a function defined with the
    // frozen lambda signature lowered from `ratchet-core` metadata. The caller
    // validates the artifact kind and keeps the owning `JITModule` alive while
    // the returned entry is called.
    let entry = unsafe { mem::transmute::<*mut u8, JitLambdaFn>(code_ptr.as_ptr()) };
    entry
}

/// Calls a shared-context finalized tier-2 chain entry with an argument run.
///
/// The chain analogue of
/// [`jit_cranelift_call_context_finalized_lambda_entry`]: it validates that
/// `body` is a tier-2 chain entry whose recorded arity matches `argv.len()`,
/// casts the finalized code pointer to [`JitLambdaArgvFn`], and invokes it
/// with `rt`, `env`, and a pointer to the caller's contiguous argument run
/// (outermost chain parameter first). A deopting execution returns a null
/// value with the deopt trap recorded in the armed runtime trap scope.
///
/// # Safety
///
/// Identical to [`jit_cranelift_call_context_finalized_lambda_entry`], with
/// one addition: every element of `argv` must be a valid runtime value owned
/// by the caller's evaluator (the compiled entry reads exactly `argv.len()`
/// 16-byte pairs from the slice's storage for the duration of the call).
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the
/// host has no reviewed by-value [`Value`] ABI,
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the body is
/// not a tier-2 chain entry of arity `argv.len()`, and
/// [`JitCraneliftNativeCallError::InvalidReturnValue`] when the body returns a
/// valid-tag [`Value`] whose payload bits violate the runtime layout.
pub unsafe fn jit_cranelift_call_context_finalized_lambda_argv_entry(
    body: &JitModuleContextFinalizedBody,
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
    argv: &[Value],
) -> Result<Value, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    let kind = body.artifact().kind();
    let arity_matches = matches!(
        kind,
        JitClifArtifactKind::Tier2LambdaChainEntry { arity } if usize::from(arity) == argv.len()
    );
    if !arity_matches {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind { kind });
    }

    let argv_entry = lambda_argv_entry_from_finalized_code(body.finalized_function().code_ptr());
    // SAFETY: The caller keeps the finalizing `JitModuleContext` (or a cloned
    // keep-alive handle) alive across this call, so the shared module's code
    // memory and every registered frozen-ABI candidate remain live. The body
    // was produced by the tier-2 chain lowerer, verified with the frozen argv
    // CLIF signature, and finalized by Cranelift; the recorded arity equals
    // `argv.len()`, so the entry reads exactly the caller's live slice, and it
    // translates the internal deopt sentinel to a valid null before returning.
    let chain_dispatched = unsafe { argv_entry(rt, env, argv.as_ptr()) };
    chain_dispatched.validate_payload().map_err(|source| {
        JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: body.finalized_function().symbol_name().to_owned(),
            value: chain_dispatched,
            source,
        }
    })?;

    Ok(chain_dispatched)
}

/// Invokes a finalized fold-step entry with a decoded `i64` accumulator.
///
/// The fold-step analogue of
/// [`jit_cranelift_call_context_finalized_lambda_argv_entry`]: it validates that
/// `body` is a fold-step entry, casts the finalized code pointer to
/// [`JitFoldStepI64AccFn`], and invokes it with `rt`, `env`, the running
/// accumulator `acc` as a plain decoded `i64`, and the current element `elem` by
/// value. The returned `i64` is the next accumulator. A deopting execution
/// records the deopt trap in the armed runtime trap scope; the caller must read
/// that flag — not the returned integer — to detect it, because on a deopt the
/// entry returns an unspecified placeholder integer.
///
/// # Safety
///
/// Identical to [`jit_cranelift_call_context_finalized_lambda_argv_entry`]: `rt`
/// must be the pinned runtime context over the caller's evaluator, `env` the
/// caller-owned environment, and `elem` a live runtime value owned by that
/// evaluator; the caller keeps `body`'s finalizing module alive across the call.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the
/// host has no reviewed by-value [`Value`] ABI and
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the body is not
/// a fold-step entry.
pub unsafe fn jit_cranelift_call_context_finalized_fold_step_i64acc_entry(
    body: &JitModuleContextFinalizedBody,
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
    acc: i64,
    elem: Value,
) -> Result<i64, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    let kind = body.artifact().kind();
    if !matches!(kind, JitClifArtifactKind::Tier2FoldStepI64AccEntry) {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind { kind });
    }

    let fold_step_entry =
        fold_step_i64acc_entry_from_finalized_code(body.finalized_function().code_ptr());
    // SAFETY: The caller keeps the finalizing `JitModuleContext` (or a cloned
    // keep-alive handle) alive across this call, so the shared module's code
    // memory stays live. The body was produced by the fold-step lowerer and
    // verified with the frozen fold-step CLIF signature, so the entry takes the
    // decoded accumulator and one live element word and returns the next decoded
    // accumulator; a deopt is recorded in the armed trap scope, never encoded in
    // the returned integer (any `i64` is a valid decoded accumulator).
    let acc_next = unsafe { fold_step_entry(rt, env, acc, elem) };
    Ok(acc_next)
}

/// Casts a finalized fold-step entry code pointer to the frozen fold-step ABI.
fn fold_step_i64acc_entry_from_finalized_code(code_ptr: NonNull<u8>) -> JitFoldStepI64AccFn {
    // SAFETY: Cranelift returned this pointer for a function defined with the
    // frozen fold-step i64-accumulator signature lowered from `ratchet-core`
    // metadata. The caller validates the artifact kind and keeps the owning
    // `JITModule` alive while the returned entry is called.
    let entry = unsafe { mem::transmute::<*mut u8, JitFoldStepI64AccFn>(code_ptr.as_ptr()) };
    entry
}

/// Casts a finalized tier-2 chain entry code pointer to the frozen argv ABI.
fn lambda_argv_entry_from_finalized_code(code_ptr: NonNull<u8>) -> JitLambdaArgvFn {
    // SAFETY: Cranelift returned this pointer for a function defined with the
    // frozen argv lambda-entry signature lowered from `ratchet-core` metadata.
    // The caller validates the artifact kind and arity and keeps the owning
    // `JITModule` alive while the returned entry is called.
    let entry = unsafe { mem::transmute::<*mut u8, JitLambdaArgvFn>(code_ptr.as_ptr()) };
    entry
}

// These tests exercise two-word-carrier codegen (tier-2 bodies, inline arith,
// candidate bridges, or two-word CLIF shape asserts), which declines on the
// one-word carrier; baseline-only until the S4b phase-2 one-word emitters land.
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use std::num::NonZeroUsize;

    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
        syntax::{Span, Symbol},
    };

    use super::*;
    use crate::{
        lower::{TIER2_NATIVE_DEPTH_BUDGET, lower_tier2_self_recursive_lambda},
        symbols::{JitRuntimeSymbolAddress, JitRuntimeSymbolAddressCandidate},
    };

    fn candidate(
        symbol_name: &str,
        role: RuntimeHelperRole,
        address: usize,
    ) -> JitRuntimeSymbolAddressCandidate {
        let address = NonZeroUsize::new(address).expect("test address is non-zero");
        JitRuntimeSymbolAddressCandidate::new(
            symbol_name.to_owned(),
            RuntimeSymbolKind::Helper(role),
            JitRuntimeSymbolAddress::new(address),
        )
    }

    #[test]
    fn finalized_tier2_entry_retains_inner_force_stack_maps() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Formal,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Formal {
                        name: Symbol::new(0),
                        default: None,
                    },
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local { slot: 0 },
                ),
            ],
            Vec::new(),
        );
        let lowering = lower_tier2_self_recursive_lambda(
            &arena,
            IrId::new(0),
            IrId::new(1),
            TIER2_NATIVE_DEPTH_BUDGET,
        )
        .expect("tier-2 parameter force lowers");
        let candidates = [
            candidate("aos_force", RuntimeHelperRole::ForcingControl, 1),
            candidate("aos_deopt", RuntimeHelperRole::Deoptimization, 2),
            candidate("aos_upval_get", RuntimeHelperRole::EnvironmentAccess, 3),
            candidate(
                "aos_jit_stack_map_enter",
                RuntimeHelperRole::SafepointControl,
                4,
            ),
            candidate(
                "aos_jit_stack_map_exit",
                RuntimeHelperRole::SafepointControl,
                5,
            ),
        ];
        let context =
            JitModuleContext::with_candidates(&candidates).expect("tier-2 module context builds");
        let body = context
            .define_and_finalize_tier2_lambda(lowering)
            .expect("tier-2 pair finalizes");

        assert!(
            body.finalized_function()
                .defined_function()
                .user_stack_maps()
                .is_empty(),
            "the exported entry adapter has no direct force"
        );
        let maps = body.finalized_function().runtime_user_stack_maps();
        assert_eq!(maps.len(), 1);
        assert!(maps[0].identity_sp_offset().is_some());
        assert_eq!(maps[0].entries().len(), 1);
    }
}
