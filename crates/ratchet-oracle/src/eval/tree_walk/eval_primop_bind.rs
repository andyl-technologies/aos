//! Strict primop binding, `select`, `foldl`, and replacement helpers.

use super::*;

mod select;

impl TreeWalk {
    pub(super) fn force_primop_value(
        &mut self,
        argument: EvalPrimOpArg,
        expected: &'static str,
        tag: ValueTag,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_value(argument.id(), argument.span(), argument.value())?;
        let value = self.force_lazy_foldl_initial_value(argument.id(), argument.span(), value)?;
        if value.tag() != tag {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument.id(),
                    expected,
                    actual: value.tag(),
                },
                argument.span(),
            ));
        }
        Ok(value)
    }

    pub(super) fn force_int_primop_value(
        &mut self,
        argument: EvalPrimOpArg,
    ) -> Result<i64, TreeWalkError> {
        let value = self.force_value(argument.id(), argument.span(), argument.value())?;
        self.expect_int(argument.id(), value, argument.span())
    }

    pub(super) fn eval_strict_ternary_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        primop: StrictTernaryPrimOp,
        first: EvalPrimOpArg,
        second: EvalPrimOpArg,
        third: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictTernaryPrimOp::FoldlStrict => {
                self.eval_foldl_strict_primop_value(id, span, first, second, third)
            }
            StrictTernaryPrimOp::ReplaceStrings => {
                self.eval_replace_strings_primop_value(id, span, first, second, third)
            }
            StrictTernaryPrimOp::Substring => {
                self.eval_substring_primop_value(id, span, first, second, third)
            }
        }
    }

    pub(super) fn eval_foldl_strict_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        op_arg: EvalPrimOpArg,
        initial_arg: EvalPrimOpArg,
        list_arg: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let op = self.force_callable_value(op_arg.id(), op_arg.span(), op_arg.value())?;
        let list_value = self.force_primop_value(list_arg, "list", ValueTag::List)?;
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_arg.id(),
                        source,
                    },
                    list_arg.span(),
                )
            })?;
            Self::clone_list_elements(list_arg.id(), list_arg.span(), list)?
        };

        let mut accumulator = initial_arg.value();
        if elements.is_empty() {
            return self.eval_lazy_foldl_initial_value(
                initial_arg.id(),
                initial_arg.span(),
                accumulator,
            );
        }
        // Tier-2 fold seam: identical to the direct `eval_foldl_strict_primop`
        // loop — at most two engine consults, native runs advance the index.
        let mut index = 0usize;
        let mut fold_consults = 0u32;
        while index < elements.len() {
            if fold_consults < 2 && self.tier1_engine.is_some() {
                fold_consults += 1;
                if let Some((consumed, folded)) =
                    self.try_tier2_foldl(id, span, op, accumulator, &elements[index..])
                {
                    accumulator = folded;
                    index += consumed;
                    continue;
                }
            }
            let element = elements[index];
            let step = self.apply_lambda_value(
                id,
                span,
                op_arg.id(),
                op,
                op_arg.span(),
                initial_arg.id(),
                accumulator,
            )?;
            let result = self.apply_lambda_value(
                id,
                span,
                op_arg.id(),
                step,
                op_arg.span(),
                list_arg.id(),
                element,
            )?;
            accumulator = self.force_value(op_arg.id(), op_arg.span(), result)?;
            index += 1;
        }

        Ok(accumulator)
    }

    pub(super) fn eval_replace_strings_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        from_arg: EvalPrimOpArg,
        to_arg: EvalPrimOpArg,
        string_arg: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let from_value = self.force_primop_value(from_arg, "list", ValueTag::List)?;
        let from_values = {
            let from = self.heap.get_list(from_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: from_arg.id(),
                        source,
                    },
                    from_arg.span(),
                )
            })?;
            Self::clone_list_elements(from_arg.id(), from_arg.span(), from)?
        };

        let to_value = self.force_primop_value(to_arg, "list", ValueTag::List)?;
        let to_values = {
            let to = self.heap.get_list(to_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: to_arg.id(),
                        source,
                    },
                    to_arg.span(),
                )
            })?;
            Self::clone_list_elements(to_arg.id(), to_arg.span(), to)?
        };

        if from_values.len() != to_values.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ReplaceStringsLengthMismatch {
                    id,
                    from_len: from_values.len(),
                    to_len: to_values.len(),
                },
                span,
            ));
        }

        let mut patterns = Vec::new();
        patterns.try_reserve_exact(from_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: from_values.len(),
                },
                span,
            )
        })?;
        for (from, replacement) in from_values.into_iter().zip(to_values) {
            let from = self.force_value(from_arg.id(), from_arg.span(), from)?;
            if from.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: from_arg.id(),
                        expected: "string",
                        actual: from.tag(),
                    },
                    from_arg.span(),
                ));
            }
            let from = {
                let string = self.heap.get_string(from).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: from_arg.id(),
                            source,
                        },
                        from_arg.span(),
                    )
                })?;
                Self::copy_bytes_for_node(from_arg.id(), from_arg.span(), string.bytes())?
            };
            patterns.push(ReplaceStringPattern { from, replacement });
        }

        let string_value = self.force_primop_value(string_arg, "string", ValueTag::String)?;
        let (source, context) = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_arg.id(),
                        source,
                    },
                    string_arg.span(),
                )
            })?;
            let source =
                Self::copy_bytes_for_node(string_arg.id(), string_arg.span(), string.bytes())?;
            let context = string
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_arg.id(),
                            source,
                        },
                        string_arg.span(),
                    )
                })?;
            (source, context)
        };

        let result = self.replace_strings_bytes(
            id,
            span,
            to_arg.id(),
            to_arg.span(),
            &source,
            context,
            &patterns,
        )?;
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_substring_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        start_arg: EvalPrimOpArg,
        len_arg: EvalPrimOpArg,
        string_arg: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let start_offset = self.force_int_primop_value(start_arg)? as u32 as i32;
        if start_offset < 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::NegativeSubstringStart {
                    id: start_arg.id(),
                    start: start_offset.into(),
                },
                start_arg.span(),
            ));
        }

        let len = self.force_int_primop_value(len_arg)? as u32 as usize;
        let value = self.force_value(string_arg.id(), string_arg.span(), string_arg.value())?;
        let string = self.coerce_to_string(string_arg.id(), value, string_arg.span())?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_arg.id(),
                        source,
                    },
                    string_arg.span(),
                )
            })?;
            string
                .substring_preserve_context(start_offset as usize, len)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_arg.id(),
                            source,
                        },
                        string_arg.span(),
                    )
                })?
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_strict_binary_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        primop: StrictBinaryPrimOp,
        first: EvalPrimOpArg,
        second: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictBinaryPrimOp::AppendContext => {
                self.eval_append_context_primop_value(id, span, first, second)
            }
            StrictBinaryPrimOp::ElemAt => self.eval_elem_at_primop_value(first, second),
            StrictBinaryPrimOp::HashString => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let algorithm =
                    self.eval_hash_algorithm(first.id(), first.span(), left, "hashString")?;
                let string = self.force_value(second.id(), second.span(), second.value())?;
                if string.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: second.id(),
                            expected: "string",
                            actual: string.tag(),
                        },
                        second.span(),
                    ));
                }
                self.eval_hash_string_value(id, span, second.id(), second.span(), string, algorithm)
            }
            StrictBinaryPrimOp::HashFile => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let algorithm =
                    self.eval_hash_algorithm(first.id(), first.span(), left, "hashFile")?;
                let path_value = self.force_value(second.id(), second.span(), second.value())?;
                self.eval_hash_file_path_value(
                    id,
                    span,
                    second.id(),
                    second.span(),
                    path_value,
                    algorithm,
                )
            }
            StrictBinaryPrimOp::CompareVersions => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let left = self.context_free_string_bytes(
                    first.id(),
                    first.span(),
                    left,
                    "compareVersions",
                )?;
                let right = self.force_value(second.id(), second.span(), second.value())?;
                let right = self.context_free_string_bytes(
                    second.id(),
                    second.span(),
                    right,
                    "compareVersions",
                )?;
                Ok(Value::int(compare_version_bytes(&left, &right)))
            }
            StrictBinaryPrimOp::Add
            | StrictBinaryPrimOp::Sub
            | StrictBinaryPrimOp::Mul
            | StrictBinaryPrimOp::Div => {
                let left = self.force_demanded_value(first.id(), first.span(), first.value())?;
                let right =
                    self.force_demanded_value(second.id(), second.span(), second.value())?;
                let left = self.expect_number(first.id(), left, first.span())?;
                let right = self.expect_number(second.id(), right, second.span())?;
                let node = self.node(id)?;
                let op = match primop {
                    StrictBinaryPrimOp::Add => BinaryArithmeticOp::Add,
                    StrictBinaryPrimOp::Sub => BinaryArithmeticOp::Sub,
                    StrictBinaryPrimOp::Mul => BinaryArithmeticOp::Mul,
                    StrictBinaryPrimOp::Div => BinaryArithmeticOp::Div,
                    _ => {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                            span,
                        ));
                    }
                };
                self.eval_numeric_values(id, node, op, left, right)
            }
            StrictBinaryPrimOp::BitAnd | StrictBinaryPrimOp::BitOr | StrictBinaryPrimOp::BitXor => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let left = self.expect_int(first.id(), left, first.span())?;
                let right = self.force_value(second.id(), second.span(), second.value())?;
                let right = self.expect_int(second.id(), right, second.span())?;
                let op = match primop {
                    StrictBinaryPrimOp::BitAnd => BitwiseOp::And,
                    StrictBinaryPrimOp::BitOr => BitwiseOp::Or,
                    StrictBinaryPrimOp::BitXor => BitwiseOp::Xor,
                    _ => {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                            span,
                        ));
                    }
                };
                Ok(Value::int(op.apply(left, right)))
            }
            StrictBinaryPrimOp::LessThan => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let right = self.force_value(second.id(), second.span(), second.value())?;
                let node = *self.node(id)?;
                self.eval_comparison_values(
                    id,
                    &node,
                    ComparisonOp::Lt,
                    first.id(),
                    first.span(),
                    left,
                    second.id(),
                    second.span(),
                    right,
                    first.span(),
                    second.span(),
                )
            }
            StrictBinaryPrimOp::All => {
                self.eval_all_any_primop_value(id, span, AllAnyOp::All, first, second)
            }
            StrictBinaryPrimOp::Any => {
                self.eval_all_any_primop_value(id, span, AllAnyOp::Any, first, second)
            }
            StrictBinaryPrimOp::Match => self.eval_match_primop_value(id, span, first, second),
            StrictBinaryPrimOp::Split => self.eval_split_primop_value(id, span, first, second),
            StrictBinaryPrimOp::ConcatMap => {
                self.eval_concat_map_primop_value(id, span, first, second)
            }
            StrictBinaryPrimOp::Filter => self.eval_filter_primop_value(id, span, first, second),
            StrictBinaryPrimOp::GenList => self.eval_gen_list_primop_value(id, span, first, second),
            StrictBinaryPrimOp::GroupBy => self.eval_group_by_primop_value(id, span, first, second),
            StrictBinaryPrimOp::Map => self.eval_map_primop_value(id, span, first, second),
            StrictBinaryPrimOp::Partition => {
                self.eval_partition_primop_value(id, span, first, second)
            }
        }
    }

    pub(super) fn bind_lambda_argument(
        &mut self,
        id: IrId,
        pattern: IrId,
        slot_count: usize,
        frame: &EvalFrame,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let pattern_node = *self.node(pattern)?;
        match pattern_node.kind {
            IrKind::Formal => {
                let IrData::Formal {
                    name: _,
                    default: None,
                } = pattern_node.data
                else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::UnsupportedLambdaPattern {
                            id,
                            pattern,
                            kind: pattern_node.kind,
                        },
                        pattern_node.span,
                    ));
                };
                if slot_count != 1 {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::LambdaFrameSlotMismatch {
                            id,
                            frame_slots: slot_count,
                            pattern_slots: 1,
                        },
                        span,
                    ));
                }
                frame.set(0, argument).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })
            }
            IrKind::FormalSet => self.bind_formal_set_argument(
                id,
                pattern,
                &pattern_node,
                slot_count,
                frame,
                argument_id,
                argument_span,
                argument,
                span,
            ),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedLambdaPattern { id, pattern, kind },
                pattern_node.span,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn bind_formal_set_argument(
        &mut self,
        id: IrId,
        pattern: IrId,
        pattern_node: &IrNode,
        slot_count: usize,
        frame: &EvalFrame,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let IrData::FormalSet {
            formals,
            ellipsis,
            alias,
        } = pattern_node.data
        else {
            return Err(self.invalid_payload(pattern, pattern_node, "formal-set payload"));
        };
        let formal_slice = self
            .current_ir()
            .arena
            .child_slice(formals)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidChildSlice {
                        id: pattern,
                        slice: formals,
                    },
                    pattern_node.span,
                )
            })?;
        let mut formal_ids = Vec::new();
        formal_ids
            .try_reserve_exact(formal_slice.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: pattern,
                        len: formal_slice.len(),
                    },
                    pattern_node.span,
                )
            })?;
        formal_ids.extend_from_slice(formal_slice);

        let mut names = Vec::new();
        names.try_reserve_exact(formal_ids.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: pattern,
                    len: formal_ids.len(),
                },
                pattern_node.span,
            )
        })?;
        for formal in &formal_ids {
            let formal_node = *self.node(*formal)?;
            let IrData::Formal { name, .. } = formal_node.data else {
                return Err(self.invalid_payload(*formal, &formal_node, "formal payload"));
            };
            if self.symbols.resolve(name).is_none() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: *formal,
                        symbol: name,
                    },
                    formal_node.span,
                ));
            }
            names.push(name);
        }
        if let Some(alias) = alias
            && self.symbols.resolve(alias).is_none()
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id: pattern,
                    symbol: alias,
                },
                pattern_node.span,
            ));
        }
        let alias_slot = alias.filter(|alias| !names.contains(alias));
        let pattern_slots = names.len() + usize::from(alias_slot.is_some());
        if slot_count != pattern_slots {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::LambdaFrameSlotMismatch {
                    id,
                    frame_slots: slot_count,
                    pattern_slots,
                },
                span,
            ));
        }

        let attrs_value = self.force_value(argument_id, argument_span, argument)?;
        let attrs_value =
            self.force_lazy_foldl_initial_value(argument_id, argument_span, attrs_value)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                argument_span,
            ));
        }

        if !ellipsis {
            let unexpected = {
                let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs
                    .iter_lexicographic()
                    .find(|entry| !names.contains(&entry.key))
                    .map(|entry| entry.key)
            };
            if let Some(symbol) = unexpected {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnexpectedFormalAttribute { id, symbol },
                    span,
                ));
            }
        }

        for (slot, formal) in formal_ids.into_iter().enumerate() {
            let formal_node = *self.node(formal)?;
            let IrData::Formal { name, default } = formal_node.data else {
                return Err(self.invalid_payload(formal, &formal_node, "formal payload"));
            };
            let selected = {
                let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(name)
            };
            let value = match (selected, default) {
                (Some(value), _) => value,
                (None, Some(default)) => self.eval_lazy_node(default)?,
                (None, None) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingFormalAttribute { id, symbol: name },
                        span,
                    ));
                }
            };
            frame.set(slot as u32, value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
            })?;
        }

        if alias_slot.is_some() {
            frame
                .set(names.len() as u32, attrs_value)
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })?;
        }

        Ok(())
    }

    pub(super) fn eval_attrset(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::AttrSet {
            shape,
            bindings,
            recursive,
            has_dynamic,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "attrset payload"));
        };
        let binding_range = self.binding_range(id, bindings, node.span)?;
        let overrides_symbol = if recursive {
            Some(self.intern_builtin_attr_symbol(id, OVERRIDES_ATTR, node.span)?)
        } else {
            None
        };
        let active_overrides_symbol = overrides_symbol.filter(|symbol| {
            binding_range.clone().any(|binding_index| {
                matches!(
                    self.current_ir().bindings[binding_index].key,
                    IrAttrPathSegment::Static(binding_symbol) if binding_symbol == *symbol
                )
            })
        });
        {
            let shape_keys = self
                .current_ir()
                .shapes
                .get(shape.index())
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidShapeId { id, shape }, node.span)
                })?
                .keys
                .to_vec();
            self.validate_attrset_shape(id, shape, &shape_keys, binding_range.clone(), node.span)?;
        }
        let static_bindings = binding_range
            .clone()
            .filter(|binding_index| {
                matches!(
                    self.current_ir().bindings[*binding_index].key,
                    IrAttrPathSegment::Static(_)
                )
            })
            .count();
        let frame_values = if recursive {
            let Some(frame) = frame else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingFrameMetadata { id },
                    node.span,
                ));
            };
            let slot_count = self.frame_info(id, frame, node.span)?.slot_count as usize;
            if slot_count != static_bindings {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetFrameSlotMismatch {
                        id,
                        frame_slots: slot_count,
                        bindings: static_bindings,
                    },
                    node.span,
                ));
            }
            Some(
                EvalFrame::new_linked(slot_count, self.env.last().cloned()).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                })?,
            )
        } else {
            None
        };
        let admit_attrset_binding_accumulator = !recursive
            && active_overrides_symbol.is_none()
            && self.can_admit_gc_stress_root_accumulator_allocation_safepoints(id);
        let mut inherit_source_thunks = BTreeMap::new();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(binding_range.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: binding_range.len(),
                        },
                    },
                    node.span,
                )
            })?;
        if let Some(frame_values) = &frame_values {
            self.push_env_frame(Arc::clone(frame_values));
        }
        self.begin_order_sensitive_binding_assembly();
        let result = (|| {
            let mut static_slots = BTreeMap::new();
            if let Some(frame_values) = &frame_values {
                self.begin_order_sensitive_binding_assembly();
                let init_result = (|| {
                    let mut slot = 0u32;
                    for binding_index in binding_range.clone() {
                        let binding = self.current_ir().bindings[binding_index];
                        if let IrAttrPathSegment::Static(symbol) = binding.key {
                            let value = self.eval_attr_binding_value(
                                id,
                                node.span,
                                binding.value,
                                &mut inherit_source_thunks,
                            )?;
                            frame_values.set(slot, value).map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                            })?;
                            static_slots.insert(symbol, slot);
                            slot += 1;
                        }
                    }
                    Ok(())
                })();
                self.end_order_sensitive_binding_assembly(init_result.is_ok());
                init_result?;
            }

            if let Some(overrides_symbol) = active_overrides_symbol {
                let Some(frame_values) = frame_values.as_ref() else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingFrameMetadata { id },
                        node.span,
                    ));
                };
                let mut slot = 0u32;
                for binding_index in binding_range.clone() {
                    let binding = self.current_ir().bindings[binding_index];
                    if let IrAttrPathSegment::Static(key) = binding.key {
                        let value = frame_values.get(slot).map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                        })?;
                        slot += 1;
                        let position = binding
                            .position
                            .map(|span| AttrPosition::new(self.current_module.as_u32(), span));
                        let entry = match position {
                            Some(position) => AttrEntry::with_position(key, value, position),
                            None => AttrEntry::new(key, value),
                        };
                        entries.push(entry);
                    }
                }

                self.apply_recursive_attrset_overrides(
                    id,
                    node.span,
                    overrides_symbol,
                    frame_values,
                    &static_slots,
                    &mut entries,
                )?;

                for binding_index in binding_range {
                    let binding = self.current_ir().bindings[binding_index];
                    if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                        continue;
                    }
                    let key = self.eval_attr_name(
                        id,
                        binding.key,
                        DynamicAttrNullPolicy::SkipNull,
                        node.span,
                    )?;
                    let Some(key) = key else {
                        continue;
                    };
                    let value = self.eval_attr_binding_value(
                        id,
                        node.span,
                        binding.value,
                        &mut inherit_source_thunks,
                    )?;
                    let position = binding
                        .position
                        .map(|span| AttrPosition::new(self.current_module.as_u32(), span));
                    let entry = match position {
                        Some(position) => AttrEntry::with_position(key, value, position),
                        None => AttrEntry::new(key, value),
                    };
                    entries.push(entry);
                }
            } else {
                let mut slot = 0u32;
                for binding_index in binding_range {
                    let binding = self.current_ir().bindings[binding_index];
                    let key = self.eval_attr_name(
                        id,
                        binding.key,
                        DynamicAttrNullPolicy::SkipNull,
                        node.span,
                    )?;
                    let Some(key) = key else {
                        continue;
                    };
                    let value = if let Some(frame_values) = &frame_values {
                        if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                            let value = frame_values.get(slot).map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                            })?;
                            slot += 1;
                            value
                        } else {
                            self.eval_attr_binding_value(
                                id,
                                node.span,
                                binding.value,
                                &mut inherit_source_thunks,
                            )?
                        }
                    } else if admit_attrset_binding_accumulator {
                        self.with_attr_entry_value_roots(
                            id,
                            node.span,
                            entries.as_mut_slice(),
                            |eval| {
                                eval.with_gc_stress_composite_accumulator_suspended(|eval| {
                                    eval.with_gc_stress_accumulator_allocation_node(
                                        binding.value,
                                        |eval| {
                                            eval.eval_attr_binding_value(
                                                id,
                                                node.span,
                                                binding.value,
                                                &mut inherit_source_thunks,
                                            )
                                        },
                                    )
                                })
                            },
                        )?
                    } else {
                        self.eval_attr_binding_value(
                            id,
                            node.span,
                            binding.value,
                            &mut inherit_source_thunks,
                        )?
                    };
                    let position = binding
                        .position
                        .map(|span| AttrPosition::new(self.current_module.as_u32(), span));
                    let entry = match position {
                        Some(position) => AttrEntry::with_position(key, value, position),
                        None => AttrEntry::new(key, value),
                    };
                    entries.push(entry);
                }
            }
            Ok(entries)
        })();
        self.end_order_sensitive_binding_assembly(result.is_ok());
        if recursive {
            self.pop_env_frame();
        }
        let entries = result?;

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        let len = attrs.len();
        let is_static_literal = !has_dynamic && active_overrides_symbol.is_none();
        let construction = if is_static_literal {
            AttrSetConstruction::StaticLiteral { len }
        } else {
            AttrSetConstruction::Dynamic { len }
        };
        self.alloc_flat_attrs_with_repr_telemetry(
            id,
            node.span,
            shape.as_u32(),
            attrs,
            construction,
        )
    }

    pub(super) fn apply_recursive_attrset_overrides(
        &mut self,
        id: IrId,
        span: Span,
        overrides_symbol: Symbol,
        frame_values: &Arc<EvalFrame>,
        static_slots: &BTreeMap<Symbol, u32>,
        entries: &mut Vec<AttrEntry>,
    ) -> Result<(), TreeWalkError> {
        let Some(overrides_slot) = static_slots.get(&overrides_symbol).copied() else {
            return Ok(());
        };
        let overrides_value = frame_values
            .get(overrides_slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))?;
        let overrides_value = self
            .force_value(id, span, overrides_value)
            .map_err(|error| self.prepend_overrides_context(id, span, error))?;
        let overrides_value = self
            .force_lazy_foldl_initial_value(id, span, overrides_value)
            .map_err(|error| self.prepend_overrides_context(id, span, error))?;
        if overrides_value.tag() != ValueTag::Attrs {
            let error = TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "attrs",
                    actual: overrides_value.tag(),
                },
                span,
            );
            return Err(self.prepend_overrides_context(id, span, error));
        }

        let override_entries = {
            let attrs = self.heap.get_attrs(overrides_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            Self::clone_attr_entries_source_order(id, span, attrs)?
        };
        entries
            .try_reserve_exact(override_entries.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: entries.len().saturating_add(override_entries.len()),
                        },
                    },
                    span,
                )
            })?;

        for override_entry in override_entries {
            if let Some(slot) = static_slots.get(&override_entry.key).copied() {
                frame_values
                    .set(slot, override_entry.value)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                    })?;
                if let Some(entry) = entries
                    .iter_mut()
                    .find(|entry| entry.key == override_entry.key)
                {
                    *entry = override_entry;
                    continue;
                }
            }
            entries.push(override_entry);
        }

        Ok(())
    }

    pub(super) fn prepend_overrides_context(
        &self,
        id: IrId,
        span: Span,
        error: TreeWalkError,
    ) -> TreeWalkError {
        error
            .try_prepend_context(
                id,
                span,
                self.context_with_current_source(b"the `__overrides` attribute".to_vec()),
            )
            .unwrap_or_else(|error| error)
    }
}
