//! Heap allocation, value interning, and attrset/path materialization helpers.

use super::*;

impl TreeWalk {
    pub(super) fn attr_value_by_name(
        &mut self,
        id: IrId,
        attrs_value: Value,
        name: &[u8],
        span: Span,
    ) -> Result<Option<Value>, TreeWalkError> {
        let symbol = self.symbols.intern(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })?;
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(attrs.get(symbol))
    }

    pub(super) fn context_free_string_bytes(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let string = self
            .heap
            .get_string(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if string.has_context() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StringContextNotAllowed { id, op },
                span,
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(string.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: string.len(),
                },
                span,
            )
        })?;
        bytes.extend_from_slice(string.bytes());
        Ok(bytes)
    }

    pub(super) fn coerce_to_filesystem_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let path = self.coerce_to_path_string(id, span, value)?;
        self.validate_filesystem_path_context(id, span, &path, op)?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok(bytes)
    }

    pub(super) fn coerce_to_filesystem_or_text_store_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<(Vec<u8>, bool), TreeWalkError> {
        let path = self.coerce_to_path_string(id, span, value)?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        if self.text_store_path_has_allowed_context(&path) {
            return Ok((bytes, true));
        }
        self.validate_filesystem_path_context(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok((bytes, false))
    }

    pub(super) fn text_store_path_has_allowed_context(&self, path: &NixString) -> bool {
        if !self.text_store.contains_key(path.bytes()) {
            return false;
        }
        path.context().iter().all(|element| {
            element.kind() == ContextKind::OpaquePath && element.path() == path.bytes()
        })
    }

    pub(super) fn coerce_to_path_string(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let path = if value.tag() == ValueTag::Path {
            self.clone_path_value(id, span, value)?
        } else {
            let string = self.coerce_to_string(id, value, span)?;
            self.clone_string_value(id, span, string)?
        };
        if !Path::new(OsStr::from_bytes(path.bytes())).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: Self::copy_bytes_for_node(id, span, path.bytes())?,
                },
                span,
            ));
        }
        Ok(path)
    }

    pub(super) fn validate_filesystem_path_context(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        let normalized_path = normalize_absolute_path_bytes(path.bytes());
        for element in path.context().iter() {
            if element.kind() != ContextKind::OpaquePath {
                continue;
            }
            if !element.path().starts_with(b"/") {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
            let normalized_context_path = normalize_absolute_path_bytes(element.path());
            if !path_is_under_root(&normalized_path, &normalized_context_path) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_ifd_path_context(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        for element in path.context().iter() {
            if element.kind() == ContextKind::OpaquePath {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn realize_import_from_derivation(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        for element in path.context().iter() {
            match element.kind() {
                ContextKind::OpaquePath => {}
                ContextKind::SingleOutput | ContextKind::DeepDerivation => {
                    let request = IfdRealization {
                        path: path.bytes(),
                        drv_path: element.path(),
                        output_name: element.output(),
                        context_kind: element.kind(),
                        op,
                    };
                    let Some(realizer) = &self.ifd_realizer else {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedImportFromDerivation {
                                id,
                                op,
                                detail: Box::new(IfdErrorDetail::new(
                                    path.bytes().to_vec(),
                                    element.path().to_vec(),
                                    element.output().map(<[u8]>::to_vec),
                                    element.kind(),
                                    None,
                                )),
                            },
                            span,
                        ));
                    };
                    self.materialize_ifd_derivation(id, span, path, element, op)?;
                    realizer.realize(request).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ImportFromDerivation {
                                id,
                                op,
                                detail: Box::new(IfdErrorDetail::new(
                                    path.bytes().to_vec(),
                                    element.path().to_vec(),
                                    element.output().map(<[u8]>::to_vec),
                                    element.kind(),
                                    Some(source.message().to_owned()),
                                )),
                            },
                            span,
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn materialize_ifd_derivation(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        let Some(path_in_store) = self.strip_configured_store_dir(element.path()) else {
            return Ok(());
        };
        let Ok(drv_path) = nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store)
        else {
            return Ok(());
        };
        if !self.known_derivations.contains_key(&drv_path) {
            return Ok(());
        }
        let mut visited = BTreeSet::new();
        self.materialize_known_derivation_closure(
            id,
            span,
            path,
            element,
            op,
            &drv_path,
            &mut visited,
        )
    }

    pub(super) fn materialize_known_derivation_closure(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
        drv_path: &nix_compat::store_path::StorePath<String>,
        visited: &mut BTreeSet<nix_compat::store_path::StorePath<String>>,
    ) -> Result<(), TreeWalkError> {
        if !visited.insert(drv_path.clone()) {
            return Ok(());
        }
        let Some(known) = self.known_derivations.get(drv_path) else {
            return Ok(());
        };
        let input_derivations: Vec<_> =
            known.derivation.input_derivations.keys().cloned().collect();
        for input in input_derivations {
            self.materialize_known_derivation_closure(
                id, span, path, element, op, &input, visited,
            )?;
        }

        let Some(known) = self.known_derivations.get(drv_path) else {
            return Ok(());
        };
        let bytes = self
            .known_derivation_aterm_bytes(drv_path, known)
            .map_err(|source| {
                self.ifd_materialization_error(id, span, path, element, op, source.to_string())
            })?;
        let absolute_path =
            PathBuf::from(OsStr::from_bytes(&self.store_path_absolute_bytes(drv_path)));
        materialize_drv(&absolute_path, &bytes).map_err(|source| {
            self.ifd_materialization_error(id, span, path, element, op, source.to_string())
        })
    }

    pub(super) fn ifd_materialization_error(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
        message: String,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::ImportFromDerivation {
                id,
                op,
                detail: Box::new(IfdErrorDetail::new(
                    path.bytes().to_vec(),
                    element.path().to_vec(),
                    element.output().map(<[u8]>::to_vec),
                    element.kind(),
                    Some(format!(
                        "failed to materialize native derivation for IFD: {message}"
                    )),
                )),
            },
            span,
        )
    }

    pub(super) fn check_filesystem_path_access(
        &self,
        id: IrId,
        span: Span,
        path: &[u8],
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Impure {
            return Ok(());
        }
        if !Path::new(OsStr::from_bytes(path)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: path.to_vec(),
                },
                span,
            ));
        }
        let normalized = normalize_absolute_path_bytes(path);
        if self.options.path_is_allowed(&normalized) {
            if let Some(resolved) = canonicalize_policy_path(path) {
                if !self.options.resolved_path_is_allowed(&resolved) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::PathAccessDenied {
                            id,
                            path: resolved,
                            mode: self.options.eval_mode(),
                        },
                        span,
                    ));
                }
            }
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::PathAccessDenied {
                id,
                path: normalized,
                mode: self.options.eval_mode(),
            },
            span,
        ))
    }

    pub(super) fn eval_attr_name(
        &mut self,
        id: IrId,
        segment: IrAttrPathSegment,
        null_policy: DynamicAttrNullPolicy,
        span: Span,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => {
                if self.symbols.resolve(symbol).is_none() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol { id, symbol },
                        span,
                    ));
                }
                Ok(Some(symbol))
            }
            IrAttrPathSegment::Dynamic(dynamic) => {
                self.eval_dynamic_attr_name(self.dynamic_attr_expression(dynamic)?, null_policy)
            }
        }
    }

    pub(super) fn dynamic_attr_expression(&self, dynamic: IrId) -> Result<IrId, TreeWalkError> {
        let node = self.node(dynamic)?;
        if node.kind == IrKind::Interp {
            if let IrData::Node(child) = node.data {
                return Ok(child);
            }
        }
        Ok(dynamic)
    }

    pub(super) fn eval_dynamic_attr_name(
        &mut self,
        expression: IrId,
        null_policy: DynamicAttrNullPolicy,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        let span = self.node(expression)?.span;
        let value = self.eval_node(expression)?;
        match value.tag() {
            ValueTag::Null if null_policy == DynamicAttrNullPolicy::SkipNull => Ok(None),
            ValueTag::String => self
                .intern_context_free_string_value(expression, value, span, "dynamic attribute name")
                .map(Some),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: expression,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn intern_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = {
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(string.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: string.len(),
                    },
                    span,
                )
            })?;
            bytes.extend_from_slice(string.bytes());
            bytes
        };
        self.intern_attr_name_bytes(id, &bytes)
    }

    pub(super) fn intern_context_free_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
        op: &'static str,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = self.context_free_string_bytes(id, span, value, op)?;
        self.intern_attr_name_bytes(id, &bytes)
    }

    pub(super) fn intern_attr_name_bytes(
        &mut self,
        id: IrId,
        bytes: &[u8],
    ) -> Result<Symbol, TreeWalkError> {
        self.symbols.intern(bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })
    }

    pub(super) fn eval_list(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Children(children) = node.data else {
            return Err(self.invalid_payload(id, node, "list children"));
        };
        let children = self
            .current_ir()
            .arena
            .child_slice(children)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidChildSlice {
                        id,
                        slice: children,
                    },
                    node.span,
                )
            })?
            .to_vec();
        let mut elements = Vec::new();
        elements.try_reserve_exact(children.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: children.len(),
                },
                node.span,
            )
        })?;
        for child in children.iter().copied() {
            elements.push(self.eval_lazy_node(child)?);
        }
        self.heap
            .alloc_list(NixList::new(elements))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    pub(super) fn eval_local_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Local { slot } = node.data else {
            return Err(self.invalid_payload(id, node, "local payload"));
        };
        let Some(frame) = self.env.last() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingEnvironment { id },
                node.span,
            ));
        };
        frame
            .get(slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    pub(super) fn eval_upval_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Upval { depth, slot } = node.data else {
            return Err(self.invalid_payload(id, node, "upvalue payload"));
        };
        let depth = depth as usize;
        if depth >= self.env.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidUpvalueDepth {
                    id,
                    depth,
                    frames: self.env.len(),
                },
                node.span,
            ));
        }
        let index = self.env.len() - 1 - depth;
        self.env[index]
            .get(slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    pub(super) fn eval_lazy_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        if node.kind == IrKind::ThunkAlloc {
            return self.eval_thunk_alloc(id, &node);
        }
        self.eval_node(id)
    }

    pub(super) fn eval_nested_equality_operand(
        &mut self,
        id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        match node.kind {
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            _ => self.eval_node(id),
        }
    }

    pub(super) fn eval_thunk_alloc(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Node(body) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        self.alloc_thunk_for_node(id, body, node.span)
    }

    pub(super) fn alloc_thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        self.node(body)?;
        let env = self.capture_env(id, span)?;
        let with_env = self.capture_with_env(id, span)?;
        let scoped_globals = self.capture_scoped_global_env(id, span)?;
        let value = self
            .heap
            .alloc_thunk(EvalThunk::with_captures(
                self.current_module,
                body,
                env,
                with_env,
                scoped_globals,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.increment_thunks_allocated();
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_apply_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self
            .heap
            .alloc_thunk(EvalThunk::apply(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                argument_id,
                argument,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.increment_thunks_allocated();
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_apply2_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        first_argument_id: IrId,
        first_argument_span: Span,
        first_argument: Value,
        second_argument_id: IrId,
        second_argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self
            .heap
            .alloc_thunk(EvalThunk::apply2(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                first_argument_id,
                first_argument_span,
                first_argument,
                self.current_module,
                second_argument_id,
                second_argument,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.increment_thunks_allocated();
        Ok(value)
    }

    pub(super) fn alloc_select_thunk(
        &mut self,
        id: IrId,
        span: Span,
        select_id: IrId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Result<Value, TreeWalkError> {
        let value = self
            .heap
            .alloc_thunk(EvalThunk::select(
                self.current_module,
                select_id,
                receiver,
                path,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.increment_thunks_allocated();
        Ok(value)
    }

    pub(super) fn alloc_builtin_attr_thunk(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Result<Value, TreeWalkError> {
        let value = self
            .heap
            .alloc_thunk(EvalThunk::builtin_attr(symbol, builtin))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.increment_thunks_allocated();
        Ok(value)
    }

    pub(super) fn force_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(value);
        }
        let forced_payload = value.payload_bits();
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        match thunk
            .cell()
            .begin_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            ForceClaim::AlreadyForced(value) => {
                self.lazy_identity_thunks.remove(&forced_payload);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            ForceClaim::Claimed(guard) => {
                let observed_body = thunk.closed_body_ref();
                if let Some(value) = self.lookup_forced_inline_expression_result(observed_body) {
                    let value = guard.finish(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                    })?;
                    self.lazy_identity_thunks.remove(&forced_payload);
                    return Ok(value);
                }

                self.increment_thunks_forced();
                let result = match thunk.kind() {
                    EvalThunkKind::Node {
                        body,
                        env,
                        with_env,
                        scoped_globals,
                    } => {
                        let thunk_env = self.clone_env_frames(id, env, span)?;
                        let thunk_with_env = self.clone_with_scopes(id, with_env, span)?;
                        let thunk_scoped_globals =
                            self.clone_scoped_globals(id, scoped_globals, span)?;
                        let saved_env = std::mem::replace(&mut self.env, thunk_env);
                        let saved_with_scopes =
                            std::mem::replace(&mut self.with_scopes, thunk_with_env);
                        let saved_scoped_globals =
                            std::mem::replace(&mut self.scoped_globals, thunk_scoped_globals);
                        let result = self
                            .with_current_module(body.module(), |eval| eval.eval_node(body.id()));
                        self.env = saved_env;
                        self.with_scopes = saved_with_scopes;
                        self.scoped_globals = saved_scoped_globals;
                        result
                    }
                    EvalThunkKind::Apply {
                        function,
                        function_span,
                        function_value,
                        argument,
                        argument_value,
                    } => self.with_current_module(function.module(), |eval| {
                        eval.apply_lambda_value(
                            id,
                            span,
                            function.id(),
                            *function_value,
                            *function_span,
                            argument.id(),
                            *argument_value,
                        )
                    }),
                    EvalThunkKind::Apply2 {
                        function,
                        function_span,
                        function_value,
                        first_argument,
                        first_argument_span,
                        first_argument_value,
                        second_argument,
                        second_argument_value,
                    } => self.with_current_module(function.module(), |eval| {
                        eval.apply_lambda_value_2(
                            id,
                            span,
                            function.id(),
                            *function_value,
                            *function_span,
                            first_argument.id(),
                            *first_argument_span,
                            *first_argument_value,
                            second_argument.id(),
                            *second_argument_value,
                        )
                    }),
                    EvalThunkKind::Select {
                        select,
                        receiver,
                        path,
                    } => self.with_current_module(select.module(), |eval| {
                        let span = eval.node(select.id())?.span;
                        let value = eval.eval_select_from_value(
                            select.id(),
                            span,
                            *receiver,
                            *path,
                            None,
                            true,
                        )?;
                        eval.force_node_result(select.id(), span, value)
                    }),
                    EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                        (*builtin).select(self, id, span, *symbol)
                    }
                };
                let value = result?;
                let value = guard.finish(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                })?;
                self.lazy_identity_thunks.remove(&forced_payload);
                self.observe_forced_inline_expression_result(observed_body, value);
                Ok(value)
            }
        }
    }
}
