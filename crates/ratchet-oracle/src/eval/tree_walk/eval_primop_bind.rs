//! Strict primop binding, `select`, `foldl`, and replacement helpers.

use super::formal_set_layout_cache::{FormalSetLayout, FormalSlot};
use super::*;

mod select;

impl TreeWalk {
    pub(super) fn force_primop_value(
        &mut self,
        argument: EvalPrimOpArg,
        expected: &'static str,
        tag: ValueTag,
    ) -> Result<Value, TreeWalkError> {
        let value =
            self.force_uncovered_primop_leaf(argument.id(), argument.span(), argument.value())?;
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
        let value =
            self.force_uncovered_primop_leaf(argument.id(), argument.span(), argument.value())?;
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
            let list = self.heap.get_list_view(list_value).map_err(|source| {
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

        #[cfg(feature = "lifetime_cohort_probe")]
        {
            let root_len = elements.len().checked_add(3).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
            let mut roots = Vec::new();
            roots.try_reserve_exact(root_len).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                        id,
                        roots: root_len,
                    },
                    span,
                )
            })?;
            roots.push(op);
            roots.push(list_value);
            roots.push(initial_arg.value());
            roots.extend_from_slice(&elements);
            return self.with_lifetime_cohort_shadow_roots(id, span, &mut roots, |eval, slots| {
                eval.eval_foldl_strict_primop_value_shadowed(
                    id,
                    span,
                    op_arg,
                    initial_arg,
                    list_arg,
                    op,
                    &elements,
                    slots.start.checked_add(2).ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?,
                )
            });
        }
        #[cfg(not(feature = "lifetime_cohort_probe"))]
        {
            self.eval_foldl_strict_primop_value_unshadowed(
                id,
                span,
                op_arg,
                initial_arg,
                list_arg,
                op,
                &elements,
            )
        }
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[allow(clippy::too_many_arguments)]
    fn eval_foldl_strict_primop_value_shadowed(
        &mut self,
        id: IrId,
        span: Span,
        op_arg: EvalPrimOpArg,
        initial_arg: EvalPrimOpArg,
        list_arg: EvalPrimOpArg,
        op: Value,
        elements: &[Value],
        accumulator_slot: usize,
    ) -> Result<Value, TreeWalkError> {
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
                    if !self.set_current_transient_value_stack_root(accumulator_slot, accumulator) {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        ));
                    }
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
            accumulator = self.force_uncovered_primop_leaf(op_arg.id(), op_arg.span(), result)?;
            if !self.set_current_transient_value_stack_root(accumulator_slot, accumulator) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                ));
            }
            index += 1;
        }

        Ok(accumulator)
    }

    #[cfg(not(feature = "lifetime_cohort_probe"))]
    #[allow(clippy::too_many_arguments)]
    fn eval_foldl_strict_primop_value_unshadowed(
        &mut self,
        id: IrId,
        span: Span,
        op_arg: EvalPrimOpArg,
        initial_arg: EvalPrimOpArg,
        list_arg: EvalPrimOpArg,
        op: Value,
        elements: &[Value],
    ) -> Result<Value, TreeWalkError> {
        let mut accumulator = initial_arg.value();
        if elements.is_empty() {
            return self.eval_lazy_foldl_initial_value(
                initial_arg.id(),
                initial_arg.span(),
                accumulator,
            );
        }
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
            accumulator = self.force_uncovered_primop_leaf(op_arg.id(), op_arg.span(), result)?;
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
            let from = self.heap.get_list_view(from_value).map_err(|source| {
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
            let to = self.heap.get_list_view(to_value).map_err(|source| {
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
            let from = self.force_uncovered_primop_leaf(from_arg.id(), from_arg.span(), from)?;
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
                let string = self.heap.get_string_view(from).map_err(|source| {
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
            let string = self.heap.get_string_view(string_value).map_err(|source| {
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
            let context = string.context().try_to_owned().map_err(|source| {
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
        let value = self.force_uncovered_primop_leaf(
            string_arg.id(),
            string_arg.span(),
            string_arg.value(),
        )?;
        let string = self.coerce_to_string(string_arg.id(), value, string_arg.span())?;
        let result = {
            let string = self.heap.get_string_view(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_arg.id(),
                        source,
                    },
                    string_arg.span(),
                )
            })?;
            string
                .try_to_owned()
                .and_then(|string| string.substring_preserve_context(start_offset as usize, len))
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
                let left =
                    self.force_uncovered_primop_leaf(first.id(), first.span(), first.value())?;
                let algorithm =
                    self.eval_hash_algorithm(first.id(), first.span(), left, "hashString")?;
                let string =
                    self.force_uncovered_primop_leaf(second.id(), second.span(), second.value())?;
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
                let left =
                    self.force_uncovered_primop_leaf(first.id(), first.span(), first.value())?;
                let algorithm =
                    self.eval_hash_algorithm(first.id(), first.span(), left, "hashFile")?;
                let path_value =
                    self.force_uncovered_primop_leaf(second.id(), second.span(), second.value())?;
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
                let left =
                    self.force_uncovered_primop_leaf(first.id(), first.span(), first.value())?;
                let left = self.context_free_string_bytes(
                    first.id(),
                    first.span(),
                    left,
                    "compareVersions",
                )?;
                let right =
                    self.force_uncovered_primop_leaf(second.id(), second.span(), second.value())?;
                let right = self.context_free_string_bytes(
                    second.id(),
                    second.span(),
                    right,
                    "compareVersions",
                )?;
                self.runtime_int_value(id, span, compare_version_bytes(&left, &right))
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
                let node = *self.node(id)?;
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
                self.eval_numeric_values(id, &node, op, left, right)
            }
            StrictBinaryPrimOp::BitAnd | StrictBinaryPrimOp::BitOr | StrictBinaryPrimOp::BitXor => {
                let left =
                    self.force_uncovered_primop_leaf(first.id(), first.span(), first.value())?;
                let left = self.expect_int(first.id(), left, first.span())?;
                let right =
                    self.force_uncovered_primop_leaf(second.id(), second.span(), second.value())?;
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
                self.runtime_int_value(id, span, op.apply(left, right))
            }
            StrictBinaryPrimOp::LessThan => {
                let left =
                    self.force_uncovered_primop_leaf(first.id(), first.span(), first.value())?;
                let right =
                    self.force_uncovered_primop_leaf(second.id(), second.span(), second.value())?;
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
        // The pattern's shape (formal names, defaults, alias slot, total slots) is
        // fixed by its immutable IR node, so it is derived and validated once and
        // reused on every application. The per-argument work below runs identically
        // whether the layout was just built or served from the cache.
        let layout = self.formal_set_layout(pattern, pattern_node)?;

        if slot_count != layout.pattern_slots() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::LambdaFrameSlotMismatch {
                    id,
                    frame_slots: slot_count,
                    pattern_slots: layout.pattern_slots(),
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

        if !layout.ellipsis() {
            let unexpected = {
                let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs
                    .iter_lexicographic()
                    .find(|entry| !layout.contains_name(entry.key))
                    .map(|entry| entry.key)
            };
            if let Some(symbol) = unexpected {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnexpectedFormalAttribute { id, symbol },
                    span,
                ));
            }
        }

        let pattern_has_alias =
            matches!(pattern_node.data, IrData::FormalSet { alias: Some(_), .. });
        for (slot, formal) in layout.entries().iter().enumerate() {
            let selected = {
                let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(formal.name)
            };
            if self.options.eval_stats_dump() {
                let absent = self
                    .current_ir()
                    .facts
                    .lambda_call_summary(pattern)
                    .and_then(|summary| summary.formals.get(slot))
                    .is_some_and(|summary| summary.cardinality == Cardinality::Absent);
                if absent {
                    if pattern_has_alias {
                        self.increment_absent_formal_alias_declines();
                    } else {
                        match (selected, formal.default) {
                            (Some(_), _) => {
                                self.increment_absent_formal_selected_value_candidates();
                            }
                            (None, Some(_)) => {
                                self.increment_absent_formal_missing_default_candidates();
                            }
                            (None, None) => self.increment_absent_formal_missing_required(),
                        }
                    }
                }
            }
            let value = match (selected, formal.default) {
                (Some(value), _) => value,
                (None, Some(default)) => self.eval_lazy_node(default)?,
                (None, None) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingFormalAttribute {
                            id,
                            symbol: formal.name,
                        },
                        span,
                    ));
                }
            };
            frame.set(slot as u32, value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
            })?;
        }

        if layout.alias_has_own_slot() {
            frame
                .set(layout.entries().len() as u32, attrs_value)
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })?;
        }

        Ok(())
    }

    /// Returns the resolved layout for a formal-set pattern, deriving it on first use.
    ///
    /// A hit clones the cached [`Arc`], so the returned layout outlives the borrow
    /// of the cache while the binder calls back into the evaluator.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::build_formal_set_layout`]. Failed
    /// derivations are not cached, so the diagnostic re-surfaces on every call.
    fn formal_set_layout(
        &mut self,
        pattern: IrId,
        pattern_node: &IrNode,
    ) -> Result<Arc<FormalSetLayout>, TreeWalkError> {
        let module = self.current_module;
        if let Some(entry) = self.formal_set_layout_cache.get(module, pattern) {
            let layout = Arc::clone(entry);
            self.formal_set_layout_cache.record_hit();
            return Ok(layout);
        }
        let layout = Arc::new(self.build_formal_set_layout(pattern, pattern_node)?);
        self.formal_set_layout_cache.record_miss();
        self.formal_set_layout_cache
            .insert(module, pattern, Arc::clone(&layout));
        Ok(layout)
    }

    /// Derives the resolved layout of a formal-set pattern from its IR node.
    ///
    /// # Errors
    ///
    /// Returns an evaluator error, in the same order an uncached bind reports it,
    /// if the pattern payload is not a formal set, the formal child slice is
    /// invalid, a formal payload is malformed, or a formal or alias name does not
    /// resolve in the symbol table.
    fn build_formal_set_layout(
        &self,
        pattern: IrId,
        pattern_node: &IrNode,
    ) -> Result<FormalSetLayout, TreeWalkError> {
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
        let mut entries = Vec::new();
        entries.try_reserve_exact(formal_slice.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: pattern,
                    len: formal_slice.len(),
                },
                pattern_node.span,
            )
        })?;
        for formal in formal_slice {
            let formal_node = *self.node(*formal)?;
            let IrData::Formal { name, default } = formal_node.data else {
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
            entries.push(FormalSlot { name, default });
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
        let alias_has_own_slot =
            alias.is_some_and(|alias| !entries.iter().any(|entry| entry.name == alias));
        let pattern_slots = entries.len() + usize::from(alias_has_own_slot);
        Ok(FormalSetLayout::new(
            entries.into_boxed_slice(),
            ellipsis,
            alias_has_own_slot,
            pattern_slots,
        ))
    }
}

mod bind_helpers;
