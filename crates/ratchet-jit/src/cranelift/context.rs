//! The shared JIT module context (`JitModuleContext`) and finalized-body
//! metadata, plus the context-finalized thunk-entry dispatch.

use super::*;

/// A shared JIT module that finalizes many artifact bodies into one code cache.
///
/// Each per-body finalization path (e.g.
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`])
/// builds a fresh [`JITModule`] for the single body it compiles, paying the
/// module's builder, symbol-table, and code-cache `mmap` setup once per body.
/// `JitModuleContext` amortizes that setup by building the module and its
/// registered runtime-symbol addresses exactly once, then defining and
/// finalizing an arbitrary number of bodies into it with
/// [`define_and_finalize`](Self::define_and_finalize). Cranelift supports
/// repeated define-then-finalize on a live `JITModule`, and code finalized by an
/// earlier call keeps its pointer valid across later ones.
///
/// The module is shared behind an [`Rc`] so each finalized body can hold an
/// out-of-band [`keep_alive`](Self::keep_alive) handle that pins the code memory
/// independently of this context. The context only borrows the module mutably for
/// the duration of a [`define_and_finalize`](Self::define_and_finalize) call;
/// dispatching a finalized body reads that body's own code pointer and never
/// borrows the context, so a define during a dispatched body's nested forcing
/// does not alias.
pub struct JitModuleContext {
    pub(crate) inner: Rc<RefCell<JitModuleContextInner>>,
}

/// The mutable interior of a [`JitModuleContext`] guarded by its [`RefCell`].
pub(crate) struct JitModuleContextInner {
    /// The shared JIT module all bodies are finalized into.
    pub(crate) module: JITModule,
    /// The registered runtime-symbol addresses baked into the module's builder,
    /// retained so each body's imports can be checked against them.
    pub(crate) registration: crate::symbols::JitRuntimeSymbolRegistrationPreflight,
    /// A monotonic counter appended to each body's export symbol name.
    ///
    /// [`module_symbol_name_for_artifact`] keys the export name on the IR root id,
    /// which is unique only within a single IR module; a shared module compiling
    /// bodies from different IR modules can collide on it. The counter guarantees a
    /// unique Cranelift export symbol per defined body.
    pub(crate) define_counter: u64,
}

/// A finalized artifact body compiled into a shared [`JitModuleContext`].
///
/// Unlike [`JitCraneliftRegisteredArtifactFinalizationPreflight`], this does not
/// own the [`JITModule`]: the code memory is kept alive by the owning
/// [`JitModuleContext`] (or a [`JitModuleContextKeepAlive`] handle), which must
/// outlive every dispatch through the body. It carries only the artifact metadata
/// (to validate the kind at the call boundary) and the finalized function (its
/// code pointer and export symbol name).
pub struct JitModuleContextFinalizedBody {
    pub(crate) artifact: JitModuleArtifactMetadata,
    pub(crate) finalized_function: JitCraneliftFinalizedFunction,
}

/// An opaque handle that keeps a [`JitModuleContext`]'s code memory alive.
///
/// A finalized body dispatched through
/// [`jit_cranelift_call_context_finalized_thunk_entry`] reads a code pointer into
/// the shared module; holding one of these alongside the body guarantees the
/// module (and thus the pointer) outlives the call. Dropping it never touches the
/// code memory, so drop order between handles and bodies is unconstrained.
pub struct JitModuleContextKeepAlive {
    _inner: Rc<RefCell<JitModuleContextInner>>,
}

impl JitModuleContext {
    /// Builds a shared JIT module with `candidates` registered as symbol addresses.
    ///
    /// The registered runtime-symbol addresses are baked into the module's builder
    /// once here; every body later finalized through
    /// [`define_and_finalize`](Self::define_and_finalize) resolves its imports
    /// against them.
    ///
    /// # Errors
    ///
    /// Returns [`JitCraneliftModuleSetupError::UnsupportedHost`],
    /// [`JitCraneliftModuleSetupError::Settings`], or
    /// [`JitCraneliftModuleSetupError::TargetIsa`] when the host ISA cannot be
    /// built, and any registration error from the candidate preflight.
    pub fn with_candidates(
        candidates: &[JitRuntimeSymbolAddressCandidate],
    ) -> Result<Self, JitCraneliftModuleSetupError> {
        let registration = jit_runtime_symbol_registration_preflight_with_candidates(candidates)?;
        let (module, _registered_symbols) =
            module_with_registered_symbols(registration.bindings())?;
        Ok(Self {
            inner: Rc::new(RefCell::new(JitModuleContextInner {
                module,
                registration,
                define_counter: 0,
            })),
        })
    }

    /// Defines and finalizes one artifact body into the shared module.
    ///
    /// Declares the body's runtime imports against the module (idempotently: an
    /// import already declared by an earlier body reuses its `FuncId`), rewrites
    /// the body against those imports, defines it under a unique export symbol, and
    /// finalizes the module so the body's code pointer becomes callable. Bodies
    /// finalized by earlier calls keep their pointers valid.
    ///
    /// # Errors
    ///
    /// Returns [`JitCraneliftModuleSetupError::Readiness`] if the artifact's
    /// runtime-symbol readiness cannot be built,
    /// [`JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration`]
    /// if the body imports a helper not registered at construction, and any
    /// Cranelift declaration, definition, or finalization error, mirroring
    /// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
    pub fn define_and_finalize(
        &self,
        artifact: JitClifArtifact,
    ) -> Result<JitModuleContextFinalizedBody, JitCraneliftModuleSetupError> {
        let inner = &mut *self.inner.borrow_mut();
        let readiness =
            require_resolved_artifact_imports(jit_module_readiness_preflight_for_artifact(&artifact)?)?;
        require_registered_artifact_imports(&readiness, &inner.registration)?;

        let base_symbol_name = module_symbol_name_for_artifact(readiness.artifact());
        inner.define_counter = inner.define_counter.saturating_add(1);
        let symbol_name = format!("{base_symbol_name}.{}", inner.define_counter);
        let artifact_metadata = readiness.artifact().clone();

        let imported_symbols =
            declare_imported_symbols(&mut inner.module, readiness.symbol_declarations())?;
        let defined_function = define_registered_artifact_function(
            &mut inner.module,
            artifact,
            &imported_symbols,
            symbol_name,
        )?;
        inner.module.finalize_definitions().map_err(|source| {
            JitCraneliftModuleSetupError::FinalizeDefinitions {
                symbol_name: defined_function.symbol_name().to_owned(),
                source,
            }
        })?;
        let code_ptr = finalized_function_pointer(&inner.module, &defined_function)?;
        let finalized_function = JitCraneliftFinalizedFunction::new(defined_function, code_ptr);

        Ok(JitModuleContextFinalizedBody {
            artifact: artifact_metadata,
            finalized_function,
        })
    }

    /// Returns a handle that keeps this context's code memory alive.
    ///
    /// Store one alongside each finalized body dispatched through
    /// [`jit_cranelift_call_context_finalized_thunk_entry`] so the shared module
    /// outlives the dispatch even after this context is dropped.
    #[must_use]
    pub fn keep_alive(&self) -> JitModuleContextKeepAlive {
        JitModuleContextKeepAlive {
            _inner: Rc::clone(&self.inner),
        }
    }
}

impl JitModuleContextFinalizedBody {
    /// Returns the artifact metadata used to validate the body's kind at dispatch.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns the finalized function (its code pointer and export symbol name).
    pub const fn finalized_function(&self) -> &JitCraneliftFinalizedFunction {
        &self.finalized_function
    }
}

/// Calls a shared-context finalized thunk body and returns its validated value.
///
/// This mirrors [`jit_cranelift_call_finalized_thunk_entry`] but dispatches a body
/// finalized into a [`JitModuleContext`] rather than one that owns its own
/// [`JITModule`]. It casts the body's finalized code pointer to the frozen thunk
/// ABI, invokes it, and validates the returned [`Value`]. The code memory is kept
/// alive by the owning context (or a [`JitModuleContextKeepAlive`]) rather than by
/// the body, so the caller must keep one alive across the call.
///
/// # Safety
///
/// The [`JitModuleContext`] that finalized `body` — or a
/// [`JitModuleContextKeepAlive`] cloned from it — must stay alive until this call
/// returns, and every native-address candidate registered into that context must
/// point to a live function with the exact frozen `extern "C"` ABI for its runtime
/// symbol. `rt` and `env` must be valid for the compiled body and every helper it
/// can call, and candidate functions must not unwind across the C ABI boundary.
/// The body must produce a valid [`Value`] tag; payload-layout violations are
/// reported as [`JitCraneliftNativeCallError::InvalidReturnValue`], but an invalid
/// enum discriminant cannot be materialized safely after crossing back into Rust.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::UnsupportedNativeValueAbi`] when the host
/// has no reviewed by-value [`Value`] ABI,
/// [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when the body is not a
/// thunk body, and [`JitCraneliftNativeCallError::InvalidReturnValue`] when the
/// body returns a valid-tag [`Value`] whose payload bits violate the runtime
/// layout.
pub unsafe fn jit_cranelift_call_context_finalized_thunk_entry(
    body: &JitModuleContextFinalizedBody,
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<Value, JitCraneliftNativeCallError> {
    require_supported_native_value_abi()?;

    if body.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: body.artifact().kind(),
        });
    }
    require_artifact_value_abi(body.artifact(), JitValueAbi::Active)?;

    let thunk_entry = thunk_entry_from_finalized_code(body.finalized_function().code_ptr());
    // SAFETY: The caller keeps the finalizing `JitModuleContext` (or a cloned
    // keep-alive handle) alive across this call, so the shared module's code memory
    // and every registered frozen-ABI candidate remain live. The body was produced
    // by this crate's thunk lowerers, verified with the frozen thunk CLIF signature,
    // and finalized by Cranelift; `rt` and `env` satisfy the frozen native ABI.
    let context_dispatched = unsafe { thunk_entry(rt, env) };
    context_dispatched.validate_payload().map_err(|source| {
        JitCraneliftNativeCallError::InvalidReturnValue {
            symbol_name: body.finalized_function().symbol_name().to_owned(),
            value: context_dispatched,
            source,
        }
    })?;

    Ok(context_dispatched)
}

