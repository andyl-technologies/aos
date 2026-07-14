//! Function application, `let`/lambda evaluation, and error-context propagation.

use super::primop_builtin_cache::{CachedPrimop, MAX_DIRECT_PRIMOP_ARGS};
use super::*;

impl TreeWalk {
    pub(super) fn eval_let(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Let {
            bindings,
            body,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "let payload"));
        };
        let Some(frame) = frame else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingFrameMetadata { id },
                node.span,
            ));
        };
        let slot_count = self.frame_info(id, frame, node.span)?.slot_count as usize;
        let binding_range = self.binding_range(id, bindings, node.span)?;
        if binding_range.len() != slot_count {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::LetFrameSlotMismatch {
                    id,
                    frame_slots: slot_count,
                    bindings: binding_range.len(),
                },
                node.span,
            ));
        }
        let frame_values =
            EvalFrame::new_linked(slot_count, self.env.last().cloned()).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
            })?;
        self.push_env_frame(Arc::clone(&frame_values));
        self.begin_order_sensitive_binding_assembly();
        let init_result = (|| {
            let mut inherit_source_thunks = BTreeMap::new();
            for (slot, binding_index) in binding_range.enumerate() {
                let binding = self.current_ir().bindings[binding_index];
                if !matches!(binding.key, IrAttrPathSegment::Static(_)) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::UnsupportedLetBindingKey { id },
                        node.span,
                    ));
                }
                if self.omits_dead_binding(id, slot)
                    && self.preflight_omitted_attr_binding_value(binding.value)?
                {
                    self.increment_thunks_elided();
                    continue;
                }
                let value = self.eval_attr_binding_value(
                    id,
                    node.span,
                    binding.value,
                    &mut inherit_source_thunks,
                )?;
                frame_values.set(slot as u32, value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                })?;
            }
            Ok(())
        })();
        self.end_order_sensitive_binding_assembly(init_result.is_ok());
        let result = init_result.and_then(|()| self.eval_node(body));
        self.pop_env_frame();
        result
    }

    pub(super) fn eval_with(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair {
            first: scope,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "with pair"));
        };
        self.node(body)?;
        let value = self.eval_lazy_node(scope)?;
        self.with_scopes
            .push(EvalWithScope::new(self.current_module, scope, value));
        let result = self.eval_node(body);
        let _ = self.with_scopes.pop();
        result
    }

    pub(super) fn eval_with_var(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::DialectScopeVar {
            site,
            symbol,
            chain,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "with-var payload"));
        };
        if self.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        }

        let scope_count = self.with_chain_scope_count(id, chain, node.span)?;
        for index in 0..scope_count {
            let scope = self.with_chain_scope(id, chain, index, node.span)?;
            let scope_ref = self.with_chain_scope_ref(id, chain, index, node.span)?;
            let scope_span = self.node_in_module(scope_ref.module(), scope)?.span;
            let scope_value = self.with_scope_value(id, scope_ref, node.span)?;
            let attrs_value = self.with_current_module(scope_ref.module(), |eval| {
                let attrs_value = eval.force_value(scope, scope_span, scope_value)?;
                eval.force_lazy_foldl_initial_value(scope, scope_span, attrs_value)
            })?;
            if attrs_value.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: scope,
                        expected: "attrs",
                        actual: attrs_value.tag(),
                    },
                    scope_span,
                ));
            }
            let AttrSelectOutcome::Hit { value, .. } = self.select_static_attr_with_cache(
                id,
                node.span,
                attrs_value,
                symbol,
                site,
                index as usize,
            )?
            else {
                continue;
            };
            return Ok(value);
        }

        self.eval_global_fallback(id, symbol, node.span, site, scope_count)
    }

    pub(super) fn eval_lambda(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Lambda {
            pattern,
            body,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "lambda payload"));
        };
        let Some(frame) = frame else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingFrameMetadata { id },
                node.span,
            ));
        };
        self.node(pattern)?;
        self.node(body)?;
        self.frame_info(id, frame, node.span)?;
        let (env, capture) = self.capture_env(id, node.span)?;
        let with_env = self.capture_with_env(id, node.span)?;
        let scoped_globals = self.capture_scoped_global_env(id, node.span)?;
        self.alloc_tree_walk_lambda_with_flat_capture(
            id,
            node.span,
            EvalLambda::with_captures(
                self.current_module,
                pattern,
                body,
                frame,
                env,
                with_env,
                scoped_globals,
            ),
            capture,
        )
    }

    pub(super) fn eval_apply(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair { first, second } = node.data else {
            return Err(self.invalid_payload(id, node, "application pair"));
        };
        self.eval_apply_expression(id, node.span, first, second)
    }

    pub(super) fn eval_apply_expression(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        argument_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let mut function = self.eval_node(function_id)?;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop)
            && !self.node_is_break_primop(function_id)?
        {
            function = self.force_demanded_value(function_id, function_span, function)?;
        }
        function = self.ensure_applicable_value(function_id, function_span, function)?;
        let argument =
            self.eval_call_argument(id, function_id, function_span, function, argument_id)?;
        self.apply_lambda_value(
            id,
            span,
            function_id,
            function,
            function_span,
            argument_id,
            argument,
        )
    }

    pub(super) fn node_is_break_primop(&self, id: IrId) -> Result<bool, TreeWalkError> {
        let node = self.node(id)?;
        let IrData::PrimOp { symbol, .. } = node.data else {
            return Ok(false);
        };
        Ok(node.kind == IrKind::PrimOp && self.symbols.resolve(symbol) == Some(b"break"))
    }

    pub(super) fn eval_primop(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let (symbol, args) = match node.data {
            IrData::PrimOp { symbol, args } => (symbol, args),
            IrData::DialectNode { op, .. } if op == aos_nix_dialect::NIX_OP_DERIVATION_STRICT => {
                return self.eval_derivation_strict(id, node);
            }
            IrData::DialectScopeVar { op, .. } if op == aos_nix_dialect::NIX_OP_WITH_VAR => {
                return self.eval_with_var(id, node);
            }
            IrData::DialectNode { op, .. } | IrData::DialectScopeVar { op, .. } => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedDialectOp { id, op },
                    node.span,
                ));
            }
            _ => return Err(self.invalid_payload(id, node, "primop payload")),
        };
        let module = self.current_module;
        let call = BuiltinCall::new(id, node.span, symbol);

        // Cache hit: the builtin and its argument ids were resolved and validated
        // on the first evaluation of this node. Because the lowered IR is
        // immutable, both stay valid, so a repeat needs neither a registry lookup
        // nor an arena child-slice access — it applies the recorded ids directly.
        if let Some(entry) = self.primop_builtin_cache.get(module, id) {
            self.primop_builtin_cache.record_hit();
            let builtin = Builtin::from_kind(entry.kind());
            return builtin.apply_direct(self, call, node, entry.args());
        }

        // Miss: resolve the builtin, preserving the original diagnostic order — an
        // invalid child slice is reported before an unsupported primop. Only
        // successful resolutions with a cacheable (direct) arity are recorded;
        // unknown-symbol, unsupported-primop, and over-arity sites fall through to
        // the registry on every call so their diagnostics stay byte-identical
        // across repeats.
        let name = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let child = self.current_ir().arena.child_slice(args).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidChildSlice { id, slice: args },
                node.span,
            )
        })?;
        let len = child.len();
        // Copy the argument ids the common (direct) arity needs into a stack
        // buffer. This is the last use of the child-slice borrow of `self`, which
        // must end before the cache insert and the `&mut self` apply below.
        let inline_len = len.min(MAX_DIRECT_PRIMOP_ARGS);
        let mut buffer = [IrId::new(0); MAX_DIRECT_PRIMOP_ARGS];
        buffer[..inline_len].copy_from_slice(&child[..inline_len]);
        let Some(builtin) = lookup_builtin(name) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                node.span,
            ));
        };
        self.primop_builtin_cache.record_miss();
        if len <= MAX_DIRECT_PRIMOP_ARGS {
            // Record the builtin and its validated argument ids so later
            // evaluations of this node skip both the registry and the arena.
            self.primop_builtin_cache.insert(
                module,
                id,
                CachedPrimop::new(builtin.kind(), &buffer[..len]),
            );
            builtin.apply_direct(self, call, node, &buffer[..len])
        } else {
            // An over-arity call cannot be a valid direct primop; leave it
            // uncached (the arity check rejects it identically every call) and
            // hand the full slice to the allocating path. Re-fetch the child
            // slice since the borrow above was released.
            let child = self.current_ir().arena.child_slice(args).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidChildSlice { id, slice: args },
                    node.span,
                )
            })?;
            let mut heap = Vec::new();
            heap.try_reserve_exact(len).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len },
                    node.span,
                )
            })?;
            heap.extend_from_slice(child);
            builtin.apply_direct(self, call, node, &heap)
        }
    }

    pub(super) fn eval_strict_unary_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        primop: StrictUnaryPrimOp,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_lazy_foldl_initial_value(argument, argument_span, value)?;
        match primop {
            StrictUnaryPrimOp::IsAttrs => Ok(Value::bool(value.tag() == ValueTag::Attrs)),
            StrictUnaryPrimOp::IsList => Ok(Value::bool(value.tag() == ValueTag::List)),
            StrictUnaryPrimOp::IsFunction => Ok(Value::bool(matches!(
                value.tag(),
                ValueTag::Lambda | ValueTag::Primop
            ))),
            StrictUnaryPrimOp::IsString => Ok(Value::bool(value.tag() == ValueTag::String)),
            StrictUnaryPrimOp::IsInt => Ok(Value::bool(value.tag() == ValueTag::Int)),
            StrictUnaryPrimOp::IsFloat => Ok(Value::bool(value.tag() == ValueTag::Float)),
            StrictUnaryPrimOp::IsBool => Ok(Value::bool(value.tag() == ValueTag::Bool)),
            StrictUnaryPrimOp::IsNull => Ok(Value::bool(value.tag() == ValueTag::Null)),
            StrictUnaryPrimOp::IsPath => Ok(Value::bool(value.tag() == ValueTag::Path)),
            StrictUnaryPrimOp::TypeOf => {
                let Some(name) = value.tag().nix_type_name() else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "weak head normal form",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                };
                self.alloc_static_string(id, span, name.as_bytes())
            }
            StrictUnaryPrimOp::Length => {
                if value.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "list",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let list = self.heap.get_list(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                let len = i64::try_from(list.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListLengthOverflow {
                            id: argument,
                            len: list.len(),
                        },
                        argument_span,
                    )
                })?;
                self.runtime_int_value(argument, argument_span, len)
            }
            StrictUnaryPrimOp::AttrNames => {
                let value = self.force_lazy_foldl_initial_value(argument, argument_span, value)?;
                if value.tag() != ValueTag::Attrs {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "attrs",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let (names, order_parity_result) = {
                    let attrs = self.heap.get_attrs(value).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?;
                    let mut names = Vec::new();
                    names.try_reserve_exact(attrs.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: attrs.len(),
                            },
                            span,
                        )
                    })?;
                    let order_parity_result = collect_checked_lexicographic_keys(
                        AttrOrderTarget::Flat(attrs),
                        &self.symbols,
                    )
                    .map(|_| ());
                    for entry in attrs.iter_lexicographic() {
                        names.push(entry.key);
                    }
                    (names, order_parity_result)
                };
                let mut elements = Vec::new();
                elements.try_reserve_exact(names.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: names.len(),
                        },
                        span,
                    )
                })?;
                for symbol in names {
                    elements.push(self.alloc_symbol_string(id, span, symbol)?);
                }
                let result = self.alloc_tree_walk_list(id, span, NixList::new(elements))?;
                self.record_attr_order_parity_telemetry(id, span, order_parity_result);
                Ok(result)
            }
            StrictUnaryPrimOp::AttrValues => {
                let value = self.force_lazy_foldl_initial_value(argument, argument_span, value)?;
                if value.tag() != ValueTag::Attrs {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "attrs",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let (values, order_parity_result) = {
                    let attrs = self.heap.get_attrs(value).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?;
                    let mut values = Vec::new();
                    values.try_reserve_exact(attrs.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: attrs.len(),
                            },
                            span,
                        )
                    })?;
                    let order_parity_result = collect_checked_lexicographic_keys(
                        AttrOrderTarget::Flat(attrs),
                        &self.symbols,
                    )
                    .map(|_| ());
                    for entry in attrs.iter_lexicographic() {
                        values.push(entry.value);
                    }
                    (values, order_parity_result)
                };
                let result = self.alloc_tree_walk_list(id, span, NixList::new(values))?;
                self.record_attr_order_parity_telemetry(id, span, order_parity_result);
                Ok(result)
            }
            StrictUnaryPrimOp::Tail => {
                if value.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "list",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let values = {
                    let list = self.heap.get_list(value).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?;
                    if list.is_empty() {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::EmptyListPrimOp {
                                id: argument,
                                op: "tail",
                            },
                            argument_span,
                        ));
                    }
                    let tail = &list.as_slice()[1..];
                    let mut values = Vec::new();
                    values.try_reserve_exact(tail.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: tail.len(),
                            },
                            span,
                        )
                    })?;
                    values.extend_from_slice(tail);
                    values
                };
                self.alloc_tree_walk_list(id, span, NixList::new(values))
            }
            StrictUnaryPrimOp::Head => {
                if value.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "list",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let list = self.heap.get_list(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                let Some(head) = list.get(0) else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::EmptyListPrimOp {
                            id: argument,
                            op: "head",
                        },
                        argument_span,
                    ));
                };
                Ok(head)
            }
            StrictUnaryPrimOp::Ceil => self.eval_float_to_int_primop(
                id,
                span,
                argument,
                value,
                f64::ceil,
                ArithmeticOp::Ceil,
            ),
            StrictUnaryPrimOp::Floor => self.eval_float_to_int_primop(
                id,
                span,
                argument,
                value,
                f64::floor,
                ArithmeticOp::Floor,
            ),
            StrictUnaryPrimOp::HasContext => {
                self.eval_has_context_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::GetContext => {
                self.eval_get_context_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::GetEnv => {
                self.eval_get_env_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::AddDrvOutputDependencies => self
                .eval_add_drv_output_dependencies_primop(id, span, argument, argument_span, value),
            StrictUnaryPrimOp::UnsafeDiscardOutputDependency => self
                .eval_unsafe_discard_output_dependency_primop(
                    id,
                    span,
                    argument,
                    argument_span,
                    value,
                ),
            StrictUnaryPrimOp::UnsafeDiscardStringContext => self
                .eval_unsafe_discard_string_context_primop(
                    id,
                    span,
                    argument,
                    argument_span,
                    value,
                ),
            StrictUnaryPrimOp::Placeholder => {
                self.eval_placeholder_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::StorePath => {
                self.eval_store_path_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::StringLength => {
                self.eval_string_length_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::BaseNameOf => {
                self.eval_base_name_of_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::DirOf => {
                self.eval_dir_of_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ParseDrvName => {
                self.eval_parse_drv_name_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::SplitVersion => {
                self.eval_split_version_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::FromJson => {
                self.eval_from_json_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::FromToml => {
                self.eval_from_toml_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::ToPath => {
                self.eval_to_path_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ToString => {
                self.eval_to_string_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ToJson => {
                self.eval_to_json_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ToXml => {
                self.eval_to_xml_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ConvertHash => {
                self.eval_convert_hash_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::FunctionArgs => {
                self.eval_function_args_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ListToAttrs => {
                self.eval_list_to_attrs_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ConcatLists => {
                self.eval_concat_lists_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::Throw => {
                self.eval_throw_abort_primop(ThrowAbortOp::Throw, argument, argument_span, value)
            }
            StrictUnaryPrimOp::Abort => {
                self.eval_throw_abort_primop(ThrowAbortOp::Abort, argument, argument_span, value)
            }
        }
    }

    pub(super) fn eval_throw_abort_primop(
        &mut self,
        op: ThrowAbortOp,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let message = self.coerce_to_string(argument, value, argument_span)?;
        let message = self.heap.get_string(message).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        let message = Self::copy_bytes_for_node(argument, argument_span, message.bytes())?;

        Err(TreeWalkError::new(
            match op {
                ThrowAbortOp::Throw => TreeWalkErrorKind::Thrown {
                    id: argument,
                    message,
                },
                ThrowAbortOp::Abort => TreeWalkErrorKind::Aborted {
                    id: argument,
                    message,
                },
            },
            argument_span,
        ))
    }

    pub(super) fn eval_add_error_context_direct(
        &mut self,
        call_id: IrId,
        call_span: Span,
        context: IrId,
        expression: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_node(expression) {
            Ok(value) => Ok(value),
            Err(error) => self.add_error_context_node_to_error(call_id, call_span, context, error),
        }
    }

    pub(super) fn eval_add_error_context_value(
        &mut self,
        call_id: IrId,
        call_span: Span,
        context: EvalPrimOpArg,
        expression: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match self.force_value(expression.id(), expression.span(), expression.value()) {
            Ok(value) => Ok(value),
            Err(error) => self.add_error_context_value_to_error(call_id, call_span, context, error),
        }
    }

    pub(super) fn add_error_context_node_to_error(
        &mut self,
        call_id: IrId,
        call_span: Span,
        context: IrId,
        error: TreeWalkError,
    ) -> Result<Value, TreeWalkError> {
        let context_span = self.node(context)?.span;
        let context_value = self.eval_node(context)?;
        let message = self.coerce_add_error_context_message(
            call_id,
            call_span,
            context,
            context_span,
            context_value,
        )?;
        Err(error.try_prepend_context(
            call_id,
            call_span,
            self.context_with_current_source(message),
        )?)
    }

    pub(super) fn add_error_context_value_to_error(
        &mut self,
        call_id: IrId,
        call_span: Span,
        context: EvalPrimOpArg,
        error: TreeWalkError,
    ) -> Result<Value, TreeWalkError> {
        let context_value = self.force_value(context.id(), context.span(), context.value())?;
        let message = self.coerce_add_error_context_message(
            call_id,
            call_span,
            context.id(),
            context.span(),
            context_value,
        )?;
        Err(error.try_prepend_context(
            call_id,
            call_span,
            self.context_with_current_source(message),
        )?)
    }

    pub(super) fn coerce_add_error_context_message(
        &mut self,
        call_id: IrId,
        call_span: Span,
        context: IrId,
        context_span: Span,
        context_value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let context_tag = context_value.tag();
        let message = match self.coerce_to_string(context, context_value, context_span) {
            Ok(message) => message,
            Err(error)
                if Self::add_error_context_message_context_applies(
                    context,
                    context_tag,
                    &error,
                ) =>
            {
                let context = self.context_with_current_source(Self::copy_bytes_for_node(
                    call_id,
                    call_span,
                    ADD_ERROR_CONTEXT_MESSAGE_CONTEXT,
                )?);
                return Err(error.try_prepend_context(call_id, call_span, context)?);
            }
            Err(error) => return Err(error),
        };
        let message = self.heap.get_string(message).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: context,
                    source,
                },
                context_span,
            )
        })?;
        Self::copy_bytes_for_node(context, context_span, message.bytes())
    }

    pub(super) fn add_error_context_message_context_applies(
        context: IrId,
        context_tag: ValueTag,
        error: &TreeWalkError,
    ) -> bool {
        matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id,
                expected: "string",
                actual,
            } if id == context && (context_tag != ValueTag::Attrs || actual == ValueTag::Attrs)
        )
    }

    pub(super) fn eval_trace_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        mode: TraceMode,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let kind = match mode {
            TraceMode::Always => EvalTraceKind::Trace,
            TraceMode::Verbose => {
                if !self.options.trace_verbose() {
                    return Ok(());
                }
                EvalTraceKind::TraceVerbose
            }
        };

        let mut message = Vec::new();
        let mut visited = Vec::new();
        self.write_trace_value(
            id,
            span,
            value_id,
            value_span,
            value,
            &mut message,
            &mut visited,
            true,
        )?;
        self.emit_trace_output(id, span, kind, message)
    }

    pub(super) fn emit_trace_output(
        &mut self,
        id: IrId,
        span: Span,
        kind: EvalTraceKind,
        message: Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        self.trace_output.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: self.trace_output.len().saturating_add(1),
                },
                span,
            )
        })?;
        self.stderr.write_trace_line(&message);
        self.trace_output.push(EvalTraceOutput::new(kind, message));
        Ok(())
    }

    pub(super) fn eval_warn_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        message_id: IrId,
        message_span: Span,
        message_value: Value,
    ) -> Result<(), TreeWalkError> {
        if message_value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: message_id,
                    expected: "string",
                    actual: message_value.tag(),
                },
                message_span,
            ));
        }
        let message = self.heap.get_string(message_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: message_id,
                    source,
                },
                message_span,
            )
        })?;
        let message = Self::copy_bytes_for_node(message_id, message_span, message.bytes())?;
        self.emit_warning_output(id, span, message.clone())?;
        if self.options.abort_on_warn() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::WarningAborted {
                    id: message_id,
                    message,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn emit_warning_output(
        &mut self,
        id: IrId,
        span: Span,
        message: Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let formatted = Self::warning_stderr_bytes(id, span, &message)?;
        self.warning_output.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: self.warning_output.len().saturating_add(1),
                },
                span,
            )
        })?;
        self.stderr.write_all(&formatted);
        self.warning_output.push(EvalWarningOutput::new(message));
        Ok(())
    }

    pub(super) fn warning_stderr_bytes(
        id: IrId,
        span: Span,
        message: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut body = message;
        while body.last() == Some(&b'\n') {
            body = &body[..body.len() - 1];
        }
        if body.is_empty() {
            return Self::copy_bytes_for_node(id, span, b"\n");
        }

        let mut out = Vec::new();
        let mut lines = body.split(|byte| *byte == b'\n');
        let first = lines.next().unwrap_or_default();
        Self::extend_bytes_for_node(id, span, &mut out, WARNING_PREFIX)?;
        if !first.is_empty() {
            Self::extend_bytes_for_node(id, span, &mut out, b" ")?;
            Self::extend_bytes_for_node(id, span, &mut out, first)?;
        }
        for line in lines {
            Self::extend_bytes_for_node(id, span, &mut out, b"\n")?;
            if !line.is_empty() {
                Self::extend_bytes_for_node(id, span, &mut out, WARNING_CONTINUATION_INDENT)?;
                Self::extend_bytes_for_node(id, span, &mut out, line)?;
            }
        }
        Self::extend_bytes_for_node(id, span, &mut out, b"\n")?;
        Ok(out)
    }
}
