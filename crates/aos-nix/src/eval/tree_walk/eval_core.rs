//! Core evaluation entry points, scope/environment management, and module bookkeeping.

use super::*;

impl TreeWalk {
    /// Creates a tree-walk evaluator over `ir`.
    pub fn new(ir: &Ir) -> Self {
        Self::with_options(ir, TreeWalkOptions::default())
    }

    /// Creates a tree-walk evaluator over `ir` with explicit runtime options.
    pub fn with_options(ir: &Ir, options: TreeWalkOptions) -> Self {
        let path_literal_base = options.path_literal_base().map(<[u8]>::to_vec);
        let parse_cache = options.parse_cache_root().map(ParseCache::new);
        Self {
            modules: vec![TreeWalkModule {
                ir: ir.clone(),
                path_literal_base,
                source: None,
            }],
            current_module: EvalModuleId::ROOT,
            symbols: ir.symbols.clone(),
            heap: EvalHeap::new(),
            env: Vec::new(),
            with_scopes: Vec::new(),
            scoped_globals: Vec::new(),
            options,
            trace_output: Vec::new(),
            warning_output: Vec::new(),
            stderr: EvalStderr::default(),
            find_file_cache: BTreeMap::new(),
            known_derivations: BTreeMap::new(),
            import_cache: BTreeMap::new(),
            parse_cache,
            #[cfg(test)]
            import_parse_cache_hits: 0,
            #[cfg(test)]
            import_parse_cache_misses: 0,
            text_store: BTreeMap::new(),
            ifd_realizer: None,
            call_depth: 0,
            lazy_identity_thunks: BTreeSet::new(),
        }
    }

    /// Creates a tree-walk evaluator with source provenance for the root IR.
    ///
    /// Use this constructor for file-backed root modules whose attribute
    /// positions should be visible through `builtins.unsafeGetAttrPos`.
    /// Source-less expression evaluation should use [`Self::with_options`],
    /// matching C++ Nix `--expr` behavior where root positions are unavailable.
    pub fn with_options_and_source(
        ir: &Ir,
        options: TreeWalkOptions,
        source_name: impl Into<Vec<u8>>,
        source: impl Into<Vec<u8>>,
    ) -> Self {
        let mut eval = Self::with_options(ir, options);
        eval.modules[EvalModuleId::ROOT.index()].source = Some(ModuleSource {
            name: source_name.into(),
            bytes: source.into(),
        });
        eval
    }

    /// Returns the evaluator heap that owns heap-backed values.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns user-facing trace output emitted so far.
    pub fn trace_output(&self) -> &[EvalTraceOutput] {
        &self.trace_output
    }

    /// Returns user-facing warning output emitted so far.
    pub fn warning_output(&self) -> &[EvalWarningOutput] {
        &self.warning_output
    }

    /// Installs the callback used to realize derivation outputs for IFD.
    pub fn set_ifd_realizer(&mut self, realizer: IfdRealizer) {
        self.ifd_realizer = Some(realizer);
    }

    /// Clears any configured IFD realizer.
    pub fn clear_ifd_realizer(&mut self) {
        self.ifd_realizer = None;
    }

    #[cfg(test)]
    pub(super) fn capture_stderr(&mut self) {
        self.stderr.capture();
    }

    #[cfg(test)]
    pub(super) fn captured_stderr(&self) -> &[u8] {
        self.stderr.captured()
    }

    #[cfg(test)]
    pub(super) fn import_parse_cache_stats(&self) -> (usize, usize) {
        (self.import_parse_cache_hits, self.import_parse_cache_misses)
    }

    pub(super) fn check_call_depth(&self, id: IrId, span: Span) -> Result<(), TreeWalkError> {
        let max = self.options.max_call_depth();
        if self.call_depth > max {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MaxCallDepthExceeded {
                    id,
                    depth: self.call_depth,
                    max,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn enter_call(&mut self, id: IrId, span: Span) -> Result<(), TreeWalkError> {
        self.check_call_depth(id, span)?;
        self.call_depth = self.call_depth.saturating_add(1);
        Ok(())
    }

    pub(super) fn leave_call(&mut self) {
        self.call_depth = self.call_depth.saturating_sub(1);
    }

    pub(super) fn visible_nix_path(&self) -> &[NixSearchPathEntry] {
        if self.options.eval_mode() == EvalMode::Pure {
            &[]
        } else {
            self.options.nix_path()
        }
    }

    /// Evaluates the IR root to weak head normal form.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if evaluation of the root node fails.
    pub fn eval_root(&mut self) -> Result<Value, TreeWalkError> {
        let root = self.current_ir().root;
        self.eval_node(root)
    }

    /// Evaluates a node to weak head normal form.
    ///
    /// This initial public node entry point is intentionally limited to scalar
    /// literal, list literal, static attrset literal, string and URI literal,
    /// control-flow, boolean operator, pipe application, string/list
    /// concatenation, attrset update, static
    /// attribute selection, lexical `let` environment, simple and formal-set
    /// lambda application, lazy `with` lookup, numeric arithmetic, numeric and
    /// string/list comparison, direct strict unary primops,
    /// scalar/string/function/list/attrset equality, and conservative thunk
    /// allocation nodes. Non-expression IR helper nodes return
    /// [`TreeWalkErrorKind::InvalidNodeKind`] when they are evaluated directly.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if `id` does not address a node in this IR, if
    /// the node payload does not match its kind, if a scalar type check fails,
    /// if thunk forcing fails, or if the node kind is not yet implemented by
    /// this evaluator slice.
    pub fn eval_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        let value = match node.kind {
            IrKind::Int => {
                let IrData::Int(value) = node.data else {
                    return Err(self.invalid_payload(id, &node, "integer payload"));
                };
                Ok(Value::int(value))
            }
            IrKind::Float => {
                let IrData::Float(value) = node.data else {
                    return Err(self.invalid_payload(id, &node, "float payload"));
                };
                Ok(Value::float(value))
            }
            IrKind::Bool => {
                let IrData::Bool(value) = node.data else {
                    return Err(self.invalid_payload(id, &node, "boolean payload"));
                };
                Ok(Value::bool(value))
            }
            IrKind::Null => {
                if node.data != IrData::None {
                    return Err(self.invalid_payload(id, &node, "empty payload"));
                }
                Ok(Value::null())
            }
            IrKind::Str | IrKind::Uri => self.eval_string(id, &node),
            IrKind::Path => self.eval_path(id, &node),
            IrKind::SearchPath => self.eval_search_path(id, &node),
            IrKind::Interp => self.eval_interp(id, &node),
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::WithVar => self.eval_with_var(id, &node),
            IrKind::GlobalVar => self.eval_global_var(id, &node),
            IrKind::BuiltinAttr => self.eval_builtin_attr(id, &node),
            IrKind::List => self.eval_list(id, &node),
            IrKind::AttrSet => self.eval_attrset(id, &node),
            IrKind::Lambda => self.eval_lambda(id, &node),
            IrKind::Apply => self.eval_apply(id, &node),
            IrKind::PrimOp => self.eval_primop(id, &node),
            IrKind::Let => self.eval_let(id, &node),
            IrKind::With => self.eval_with(id, &node),
            IrKind::If => self.eval_if(id, &node),
            IrKind::Assert => self.eval_assert(id, &node),
            IrKind::UnaryOp => self.eval_unary(id, &node),
            IrKind::BinOp => self.eval_binary(id, &node),
            IrKind::Select => self.eval_select(id, &node),
            IrKind::HasAttr => self.eval_has_attr(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            IrKind::DerivationStrict => self.eval_derivation_strict(id, &node),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidNodeKind { id, kind },
                node.span,
            )),
        }?;
        self.force_node_result(id, node.span, value)
    }

    pub(super) fn force_node_result(
        &mut self,
        id: IrId,
        span: Span,
        mut value: Value,
    ) -> Result<Value, TreeWalkError> {
        loop {
            if self.is_suspended_lazy_identity_thunk(id, span, value)? {
                return Ok(value);
            }
            if !value.is_thunk() {
                return Ok(value);
            }
            let forced = self.force_value(id, span, value)?;
            if forced.raw_eq(value) {
                return Ok(forced);
            }
            value = forced;
        }
    }

    pub(super) fn is_suspended_lazy_identity_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() || !self.lazy_identity_thunks.contains(&value.payload_bits()) {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let state = thunk
            .cell()
            .state()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        Ok(state == ThunkState::Suspended)
    }

    pub(super) fn mark_lazy_identity_thunk(&mut self, value: Value) {
        if value.is_thunk() {
            self.lazy_identity_thunks.insert(value.payload_bits());
        }
    }

    pub(super) fn eval_lazy_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_path_literal_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        self.mark_lazy_identity_thunk(value);
        Ok(value)
    }

    pub(super) fn is_path_literal_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let Some(body) = thunk.body_ref() else {
            return Ok(false);
        };
        Ok(self.node_in_module(body.module(), body.id())?.kind == IrKind::Path)
    }

    pub(super) fn consume_suspended_lazy_identity_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if self.is_suspended_lazy_identity_thunk(id, span, value)? {
            self.lazy_identity_thunks.remove(&value.payload_bits());
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn force_demanded_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        let value = self.force_value(id, span, value)?;
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        Ok(value)
    }

    pub(super) fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.node_in_module(self.current_module, id)
    }

    pub(super) fn node_in_module(
        &self,
        module: EvalModuleId,
        id: IrId,
    ) -> Result<&IrNode, TreeWalkError> {
        self.module_ir(module)?.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    pub(super) fn current_ir(&self) -> &Ir {
        &self.modules[self.current_module.index()].ir
    }

    pub(super) fn module_path_literal_base(
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

    pub(super) fn module_ir(&self, module: EvalModuleId) -> Result<&Ir, TreeWalkError> {
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

    pub(super) fn module_source(
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

    pub(super) fn with_current_module<T>(
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

    pub(super) fn push_module(
        &mut self,
        id: IrId,
        span: Span,
        ir: Ir,
        path_literal_base: Vec<u8>,
        source_name: Vec<u8>,
        source: Vec<u8>,
    ) -> Result<EvalModuleId, TreeWalkError> {
        let raw = u32::try_from(self.modules.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::TooManyModules {
                    id,
                    modules: self.modules.len(),
                },
                span,
            )
        })?;
        self.modules.push(TreeWalkModule {
            ir,
            path_literal_base: Some(path_literal_base),
            source: Some(ModuleSource {
                name: source_name,
                bytes: source,
            }),
        });
        Ok(EvalModuleId::new(raw))
    }

    pub(super) fn binding_range(
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

    pub(super) fn frame_info(
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

    pub(super) fn capture_env(&self, id: IrId, span: Span) -> Result<EvalEnv, TreeWalkError> {
        EvalEnv::capture(&self.env)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(super) fn capture_with_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalWithEnv, TreeWalkError> {
        EvalWithEnv::capture(&self.with_scopes)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(super) fn capture_scoped_global_env(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalScopedGlobalEnv, TreeWalkError> {
        EvalScopedGlobalEnv::capture(&self.scoped_globals)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    pub(super) fn clone_env_frames(
        &self,
        id: IrId,
        env: &EvalEnv,
        span: Span,
    ) -> Result<Vec<Rc<EvalFrame>>, TreeWalkError> {
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

    pub(super) fn clone_with_scopes(
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

    pub(super) fn clone_scoped_globals(
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

    pub(super) fn validate_attrset_shape(
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

    pub(super) fn attr_path(
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

    pub(super) fn attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.attr_path(id, path, span)
            .map(|segments| segments.len())
    }

    pub(super) fn reject_empty_attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let len = self.attr_path_len(id, path, span)?;
        self.reject_empty_attr_path_len(id, path, span, len)
    }

    pub(super) fn reject_empty_attr_path_len(
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

    pub(super) fn attr_path_segment(
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

    pub(super) fn with_chain_scope_count(
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

    pub(super) fn with_chain_scope(
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

    pub(super) fn with_chain_scope_ref(
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

    pub(super) fn with_scope_value(
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

    pub(super) fn eval_global_fallback(
        &self,
        id: IrId,
        symbol: Symbol,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if let Some(value) = self.scoped_global_value(id, symbol, span)? {
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

    pub(super) fn scoped_global_value(
        &self,
        id: IrId,
        symbol: Symbol,
        span: Span,
    ) -> Result<Option<Value>, TreeWalkError> {
        if self.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            ));
        }

        for scope in self.scoped_globals.iter().rev().copied() {
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
            let selected = {
                let attrs = self.heap.get_attrs(scope).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(symbol)
            };
            if let Some(value) = selected {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub(super) fn eval_global_var(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "global symbol payload"));
        };
        let Some(name) = self.symbols.resolve(symbol) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        };
        if let Some(value) = self.scoped_global_value(id, symbol, node.span)? {
            return Ok(value);
        }
        if !self.scoped_globals.is_empty()
            && name != b"builtins"
            && !is_unshadowable_global_name(name)
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                node.span,
            ));
        }
        if name == b"builtins" {
            return self.eval_builtins_attrset(id, node.span);
        }
        if is_unshadowable_global_name(name) {
            if let Some(builtin) = lookup_builtin(name).filter(|builtin| builtin.is_available(self))
            {
                return self.eval_builtin_attrset_value(id, node.span, symbol, builtin);
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnresolvedGlobalVar { id, symbol },
            node.span,
        ))
    }

    pub(super) fn eval_builtin_attr(
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

    pub(super) fn eval_builtins_attrset(
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
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    pub(super) fn eval_builtin_attrset_value(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Result<Value, TreeWalkError> {
        if builtin.execution() == BuiltinExecution::BuiltinsValue {
            return self.alloc_thunk_for_node(id, id, span);
        }
        if builtin.execution() == BuiltinExecution::NixPathValue {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        if self.reject_unconfigured_impure_builtin_constant(builtin) && !builtin.is_available(self)
        {
            return self.alloc_builtin_attr_thunk(id, span, symbol, builtin);
        }
        builtin.select(self, id, span, symbol)
    }
}
