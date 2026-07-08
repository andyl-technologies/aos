//! Module, environment, scope, attr-path, and scoped-global helpers.

use super::*;
use crate::compile::IrInlineCacheSiteId;

impl TreeWalk {
    pub(super) fn cache_module_identity_hash(module: &TreeWalkModule) -> Option<DurableBlake3Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_module_source_identity(&mut hasher, module, true)?;
        module
            .force_cache_options
            .update_cache_identity(&mut hasher)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    pub(super) fn cache_synthetic_builtin_module_identity_hash(
        module: &TreeWalkModule,
        execution: BuiltinExecution,
    ) -> Option<DurableBlake3Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_module_source_identity(&mut hasher, module, false)?;
        module
            .force_cache_options
            .update_synthetic_builtin_cache_identity(&mut hasher, execution)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    pub(super) fn cache_first_class_primop_module_identity_hash(
        module: &TreeWalkModule,
        execution: BuiltinExecution,
    ) -> Option<DurableBlake3Hash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION);
        Self::update_cache_module_source_identity(&mut hasher, module, false)?;
        module
            .force_cache_options
            .update_first_class_primop_cache_identity(&mut hasher, execution)?;
        Some(DurableBlake3Hash::from_hasher(hasher))
    }

    fn update_cache_module_source_identity(
        hasher: &mut blake3::Hasher,
        module: &TreeWalkModule,
        include_path_literal_base: bool,
    ) -> Option<()> {
        match &module.source {
            Some(source) => {
                hasher.update(b"source-v1");
                Self::update_cache_identity_chunk(hasher, &source.name)?;
                Self::update_cache_identity_chunk(hasher, &source.bytes)?;
            }
            None => {
                hasher.update(b"lowered-ir-v1");
                let ir_hash = lowered_ir_fingerprint(&module.ir).ok()?;
                let ir_hash_bytes = ir_hash.as_durable_hash().as_bytes();
                Self::update_cache_identity_chunk(hasher, &ir_hash_bytes)?;
            }
        }
        if include_path_literal_base {
            match &module.path_literal_base {
                Some(path_literal_base) => {
                    hasher.update(b"path-literal-base");
                    Self::update_cache_identity_chunk(hasher, path_literal_base)?;
                }
                None => {
                    hasher.update(b"no-path-literal-base");
                }
            }
        } else {
            hasher.update(b"path-literal-base-ignored");
        }
        Some(())
    }

    pub(super) fn update_cache_identity_chunk(
        hasher: &mut blake3::Hasher,
        chunk: &[u8],
    ) -> Option<()> {
        let len = u64::try_from(chunk.len()).ok()?;
        hasher.update(&len.to_le_bytes());
        hasher.update(chunk);
        Some(())
    }

    pub(in crate::eval::tree_walk) fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.node_in_module(self.current_module, id)
    }

    pub(in crate::eval::tree_walk) fn node_in_module(
        &self,
        module: EvalModuleId,
        id: IrId,
    ) -> Result<&IrNode, TreeWalkError> {
        self.module_ir(module)?.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    pub(in crate::eval::tree_walk) fn current_ir(&self) -> &Ir {
        &self.modules[self.current_module.index()].ir
    }

    pub(in crate::eval::tree_walk) fn module_path_literal_base(
        &self,
        module: EvalModuleId,
        span: Span,
    ) -> Result<Option<&[u8]>, TreeWalkError> {
        self.modules
            .get(module.index())
            .map(|module| module.path_literal_base.as_deref())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidModuleId {
                        module: module.as_u32(),
                    },
                    span,
                )
            })
    }

    pub(in crate::eval::tree_walk) fn module_ir(
        &self,
        module: EvalModuleId,
    ) -> Result<&Ir, TreeWalkError> {
        self.modules
            .get(module.index())
            .map(|module| &module.ir)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidModuleId {
                        module: module.as_u32(),
                    },
                    Span::default(),
                )
            })
    }

    pub(in crate::eval::tree_walk) fn module_source(
        &self,
        module: EvalModuleId,
        span: Span,
    ) -> Result<Option<&ModuleSource>, TreeWalkError> {
        self.modules
            .get(module.index())
            .map(|module| module.source.as_ref())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidModuleId {
                        module: module.as_u32(),
                    },
                    span,
                )
            })
    }

    pub(in crate::eval::tree_walk) fn with_current_module<T>(
        &mut self,
        module: EvalModuleId,
        f: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.module_ir(module)?;
        let saved = self.current_module;
        self.current_module = module;
        let result = f(self);
        self.current_module = saved;
        result
    }

    pub(in crate::eval::tree_walk) fn push_module(
        &mut self,
        id: IrId,
        span: Span,
        ir: Ir,
        path_literal_base: Vec<u8>,
        source_name: Vec<u8>,
        source: Vec<u8>,
    ) -> Result<EvalModuleId, TreeWalkError> {
        let module = TreeWalkModule::new(
            ir,
            Some(path_literal_base),
            ForceCacheOptionsIdentity::new(&self.options),
            Some(ModuleSource {
                name: source_name,
                bytes: source,
            }),
        );
        let raw = if self.shared.is_some() {
            // Parallel mode: module ids are allocated from the shared
            // registry so any worker can resolve any worker's thunk bodies.
            self.publish_shared_module(module).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::TooManyModules {
                        id,
                        modules: self.modules.len(),
                    },
                    span,
                )
            })?
        } else {
            let raw = u32::try_from(self.modules.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::TooManyModules {
                        id,
                        modules: self.modules.len(),
                    },
                    span,
                )
            })?;
            self.modules.push(module);
            raw
        };
        Ok(EvalModuleId::new(raw))
    }

    pub(in crate::eval::tree_walk) fn omits_dead_binding(
        &self,
        let_node: IrId,
        binding_index: usize,
    ) -> bool {
        self.modules[self.current_module.index()]
            .dead_binding_eliminations
            .contains(let_node, binding_index)
    }

    pub(in crate::eval::tree_walk) fn binding_range(
        &self,
        id: IrId,
        slice: IrBindingSlice,
        span: Span,
    ) -> Result<std::ops::Range<usize>, TreeWalkError> {
        let start = slice.start as usize;
        let end = start.checked_add(slice.len()).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidBindingSlice { id, slice }, span)
        })?;
        if self.current_ir().bindings.get(start..end).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidBindingSlice { id, slice },
                span,
            ));
        }
        Ok(start..end)
    }

    pub(in crate::eval::tree_walk) fn frame_info(
        &self,
        id: IrId,
        frame: FrameId,
        span: Span,
    ) -> Result<&crate::compile::FrameInfo, TreeWalkError> {
        self.current_ir().frames.get(frame.index()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidFrameId {
                    id,
                    frame: frame.as_u32(),
                },
                span,
            )
        })
    }

    pub(in crate::eval::tree_walk) fn capture_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalEnv, TreeWalkError> {
        EvalEnv::capture(&self.env)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(in crate::eval::tree_walk) fn capture_with_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalWithEnv, TreeWalkError> {
        EvalWithEnv::capture(&self.with_scopes)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(in crate::eval::tree_walk) fn capture_scoped_global_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalScopedGlobalEnv, TreeWalkError> {
        EvalScopedGlobalEnv::capture(&self.scoped_globals)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(in crate::eval::tree_walk) fn clone_env_frames(
        &self,
        id: IrId,
        env: &EvalEnv,
        span: Span,
    ) -> Result<Vec<Arc<EvalFrame>>, TreeWalkError> {
        let frames = env.frames();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(frames.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: frames.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(frames);
        Ok(cloned)
    }

    pub(in crate::eval::tree_walk) fn clone_with_scopes(
        &self,
        id: IrId,
        env: &EvalWithEnv,
        span: Span,
    ) -> Result<Vec<EvalWithScope>, TreeWalkError> {
        let scopes = env.scopes();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(scopes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::WithCaptureAllocationFailed {
                        scopes: scopes.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(scopes);
        Ok(cloned)
    }

    pub(in crate::eval::tree_walk) fn clone_scoped_globals(
        &self,
        id: IrId,
        env: &EvalScopedGlobalEnv,
        span: Span,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let scopes = env.scopes();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(scopes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::ScopedGlobalCaptureAllocationFailed {
                        scopes: scopes.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(scopes);
        Ok(cloned)
    }

    pub(in crate::eval::tree_walk) fn validate_attrset_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
        shape_keys: &[Symbol],
        binding_range: std::ops::Range<usize>,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let mut binding_keys = 0usize;
        for binding_index in binding_range {
            let binding = self.current_ir().bindings[binding_index];
            let actual = match binding.key {
                IrAttrPathSegment::Static(symbol) => symbol,
                IrAttrPathSegment::Dynamic(_) => continue,
            };
            let Some(expected) = shape_keys.get(binding_keys).copied() else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                        id,
                        shape,
                        shape_keys: shape_keys.len(),
                        binding_keys: binding_keys + 1,
                    },
                    span,
                ));
            };
            if expected != actual {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetShapeKeyMismatch {
                        id,
                        shape,
                        index: binding_keys,
                        expected,
                        actual,
                    },
                    span,
                ));
            }
            binding_keys += 1;
        }

        if binding_keys != shape_keys.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                    id,
                    shape,
                    shape_keys: shape_keys.len(),
                    binding_keys,
                },
                span,
            ));
        }

        Ok(())
    }

    pub(in crate::eval::tree_walk) fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<&[IrAttrPathSegment], TreeWalkError> {
        self.current_ir()
            .attr_paths
            .get(path.index())
            .map(|segments| segments.as_ref())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    pub(in crate::eval::tree_walk) fn attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.attr_path(id, path, span)
            .map(|segments| segments.len())
    }

    pub(in crate::eval::tree_walk) fn reject_empty_attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let len = self.attr_path_len(id, path, span)?;
        self.reject_empty_attr_path_len(id, path, span, len)
    }

    pub(in crate::eval::tree_walk) fn reject_empty_attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
        len: usize,
    ) -> Result<(), TreeWalkError> {
        if len == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidAttrPath { id, path },
                span,
            ));
        }
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn attr_path_segment(
        &self,
        id: IrId,
        path: IrAttrPathId,
        index: usize,
        span: Span,
    ) -> Result<IrAttrPathSegment, TreeWalkError> {
        self.attr_path(id, path, span)?
            .get(index)
            .copied()
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    pub(in crate::eval::tree_walk) fn with_chain_scope_count(
        &self,
        id: IrId,
        chain: u32,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.current_ir()
            .with_chains
            .get(chain as usize)
            .map(|chain| chain.scopes.len())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    pub(in crate::eval::tree_walk) fn with_chain_scope(
        &self,
        id: IrId,
        chain: u32,
        index: usize,
        span: Span,
    ) -> Result<IrId, TreeWalkError> {
        self.current_ir()
            .with_chains
            .get(chain as usize)
            .and_then(|chain| chain.scopes.get(index).copied())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    pub(in crate::eval::tree_walk) fn with_chain_scope_ref(
        &self,
        id: IrId,
        chain: u32,
        index: usize,
        span: Span,
    ) -> Result<EvalNodeRef, TreeWalkError> {
        Ok(EvalNodeRef::new(
            self.current_module,
            self.with_chain_scope(id, chain, index, span)?,
        ))
    }

    pub(in crate::eval::tree_walk) fn with_scope_value(
        &self,
        id: IrId,
        scope: EvalNodeRef,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        self.with_scopes
            .iter()
            .rev()
            .find(|active| active.scope_ref() == scope)
            .map(EvalWithScope::value)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::MissingWithScope {
                        id,
                        scope: scope.id(),
                    },
                    span,
                )
            })
    }

    pub(in crate::eval::tree_walk) fn eval_global_fallback(
        &mut self,
        id: IrId,
        symbol: Symbol,
        span: Span,
        site: IrInlineCacheSiteId,
        path_index_base: usize,
    ) -> Result<Value, TreeWalkError> {
        if let Some(value) = self.scoped_global_value(id, symbol, span, site, path_index_base)? {
            return Ok(value);
        }
        match self.symbols.resolve(symbol) {
            Some(b"true") => Ok(Value::bool(true)),
            Some(b"false") => Ok(Value::bool(false)),
            Some(b"null") => Ok(Value::null()),
            Some(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                span,
            )),
            None => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            )),
        }
    }

    pub(in crate::eval::tree_walk) fn scoped_global_value(
        &mut self,
        id: IrId,
        symbol: Symbol,
        span: Span,
        site: IrInlineCacheSiteId,
        path_index_base: usize,
    ) -> Result<Option<Value>, TreeWalkError> {
        if self.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            ));
        }

        for index in (0..self.scoped_globals.len()).rev() {
            let scope = self.scoped_globals[index];
            if scope.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: scope.tag(),
                    },
                    span,
                ));
            }
            let path_index = path_index_base + self.scoped_globals.len() - 1 - index;
            if let AttrSelectOutcome::Hit { value, .. } =
                self.select_static_attr_with_cache(id, span, scope, symbol, site, path_index)?
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub(in crate::eval::tree_walk) fn eval_global_var(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::GlobalVar { site, symbol } = node.data else {
            return Err(self.invalid_payload(id, node, "global-var payload"));
        };
        let Some(name) = self.symbols.resolve(symbol) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        };
        let is_current_position = name == CUR_POS_ATTR;
        let is_nix_path = name == NIX_PATH_ATTR;
        let is_builtins = name == b"builtins";
        let is_unshadowable_global = is_unshadowable_global_name(name);
        let available_builtin = is_unshadowable_global
            .then(|| lookup_builtin(name).filter(|builtin| builtin.is_available(self)))
            .flatten();

        if is_current_position {
            return self.eval_current_position(id, node.span);
        }
        if is_nix_path {
            return self.eval_nix_path_value(id, node.span);
        }
        if let Some(value) = self.scoped_global_value(id, symbol, node.span, site, 0)? {
            return Ok(value);
        }
        if !self.scoped_globals.is_empty() && !is_builtins && !is_unshadowable_global {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                node.span,
            ));
        }
        if is_builtins {
            return self.eval_builtins_attrset(id, node.span);
        }
        if let Some(builtin) = available_builtin {
            return self.eval_builtin_attrset_value(id, node.span, symbol, builtin);
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnresolvedGlobalVar { id, symbol },
            node.span,
        ))
    }

    pub(in crate::eval::tree_walk) fn eval_builtin_attr(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "builtin attr symbol payload"));
        };
        let Some(builtin) = lookup_builtin_by_symbol(&self.symbols, symbol) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedBuiltinAttr { id, symbol },
                node.span,
            ));
        };
        if !builtin.is_available(self) {
            if self.reject_unconfigured_impure_builtin_constant(builtin) {
                return Err(self.unsupported_ambient_builtin_constant(id, node.span));
            }
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol },
                node.span,
            ));
        }
        builtin.select(self, id, node.span, symbol)
    }

    pub(in crate::eval::tree_walk) fn eval_builtins_attrset(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(BUILTINS.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: BUILTINS.len(),
                    },
                },
                span,
            )
        })?;

        for builtin in BUILTINS.iter().copied() {
            if !builtin.is_available(self)
                && !self.reject_unconfigured_impure_builtin_constant(builtin)
            {
                continue;
            }
            let symbol = self.intern_builtin_attr_symbol(id, builtin.name(), span)?;
            let value = self.eval_builtin_attrset_value(id, span, symbol, builtin)?;
            entries.push(AttrEntry::new(symbol, value));
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(in crate::eval::tree_walk) fn eval_builtin_attrset_value(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Result<Value, TreeWalkError> {
        if builtin.execution() == BuiltinExecution::BuiltinsValue {
            return self.alloc_thunk_for_node(id, id, span);
        }
        if Self::builtin_execution_is_delayed_attrset_value(builtin.execution()) {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        if self.reject_unconfigured_impure_builtin_constant(builtin) && !builtin.is_available(self)
        {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        builtin.select(self, id, span, symbol)
    }

    const fn builtin_execution_is_delayed_attrset_value(execution: BuiltinExecution) -> bool {
        Self::builtin_execution_is_force_cache_observation_safe(execution)
            || matches!(execution, BuiltinExecution::NixPathValue)
    }
}
