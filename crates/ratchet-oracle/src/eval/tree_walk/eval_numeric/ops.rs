//! Numeric, concatenation, update, and comparison operator helpers.

use super::*;

struct AttrUpdateOperand {
    entries: Vec<AttrEntry>,
    metadata: EvalHeapAttrsMetadata,
}

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_numeric_negation(
        &mut self,
        _id: IrId,
        _node: &IrNode,
        operand: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_number_node(operand)? {
            Number::Int(value) => Ok(Value::int(value.wrapping_neg())),
            // C++ Nix parses `-e` as `__sub 0 e`, so float negation is a
            // subtraction from positive zero: `-0.0` evaluates to `0.0`
            // (IEEE `0.0 - 0.0` is positive zero), never to negative zero.
            Number::Float(value) => Ok(Value::float(0.0 - value)),
        }
    }

    pub(in crate::eval::tree_walk) fn eval_numeric_binary(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let left = self
            .expect_number(lhs, left, lhs_span)
            .map_err(|error| self.label_binary_operand_error(error, lhs_span, rhs_span))?;
        let right = self
            .expect_number(rhs, right, rhs_span)
            .map_err(|error| self.label_binary_operand_error(error, lhs_span, rhs_span))?;
        self.eval_numeric_values(id, node, op, left, right)
    }

    pub(in crate::eval::tree_walk) fn eval_bitwise_primop(
        &mut self,
        op: BitwiseOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left = self.eval_int_node(lhs)?;
        let right = self.eval_int_node(rhs)?;

        Ok(Value::int(op.apply(left, right)))
    }

    pub(in crate::eval::tree_walk) fn eval_numeric_values(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: Number,
        right: Number,
    ) -> Result<Value, TreeWalkError> {
        match (left, right) {
            (Number::Int(left), Number::Int(right)) => {
                self.eval_integer_binary(id, node, op, left, right)
            }
            (left, right) => {
                self.eval_float_binary(id, node, op, left.to_float(), right.to_float())
            }
        }
    }

    pub(in crate::eval::tree_walk) fn concat_strings(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let concatenated = {
            let left = self.heap.get_string(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            let right = self.heap.get_string(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            left.concat(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, node.span)
            })?
        };
        self.alloc_tree_walk_string(id, node.span, concatenated)
    }

    pub(in crate::eval::tree_walk) fn eval_list_concat(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        if left.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "list",
                    actual: left.tag(),
                },
                lhs_span,
            ));
        }

        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        if right.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: rhs,
                    expected: "list",
                    actual: right.tag(),
                },
                rhs_span,
            ));
        }

        self.concat_lists(id, node, left, right)
    }

    pub(in crate::eval::tree_walk) fn eval_attr_update(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_lazy_foldl_initial_value(lhs, lhs_span, left)?;
        // The left operand type-checks before the right operand evaluates, so
        // a non-attrset left reports its type error even when forcing the
        // right operand would fail.
        if left.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "attrs",
                    actual: left.tag(),
                },
                lhs_span,
            ));
        }
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_lazy_foldl_initial_value(rhs, rhs_span, right)?;
        if !self.attr_update_telemetry_enabled {
            return self
                .merge_attr_update_fast(id, node.span, lhs, lhs_span, left, rhs, rhs_span, right);
        }
        let left_operand = self.attr_entries_for_update(id, lhs, lhs_span, left)?;
        let right_operand = self.attr_entries_for_update(id, rhs, rhs_span, right)?;
        self.merge_attr_update_entries(id, node.span, lhs, left_operand, right_operand)
    }

    /// Returns the process-default toggle for per-merge attrset telemetry.
    ///
    /// Telemetry defaults on under `cfg(test)` so measurement-asserting unit
    /// tests observe the full pipeline, and off in production binaries where
    /// nothing consumes it. Setting `AOS_NIX_ATTR_TELEMETRY` to anything but
    /// `0` re-enables it for release-binary measurement runs.
    pub(in crate::eval::tree_walk) fn attr_update_telemetry_default() -> bool {
        cfg!(test)
            || std::env::var_os("AOS_NIX_ATTR_TELEMETRY").is_some_and(|value| value != "0")
    }

    /// Overrides the per-merge attrset telemetry toggle for tests.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn set_attr_update_telemetry_enabled(&mut self, enabled: bool) {
        self.attr_update_telemetry_enabled = enabled;
    }

    /// Merges two forced attrset operands without recording merge telemetry.
    ///
    /// This is the production `//` path: when `right`'s keys are a subset of
    /// `left`'s, the shape-preserving [`FlatAttrs::update_right_biased_same_keys`]
    /// fast path copies `left`'s layout and overwrites the overridden slots -
    /// no permutation merge and, under [`AttrShapeMode::Record`], the result
    /// keeps `left`'s projected hidden-class shape id so later selects stay
    /// on the record-resident shaped fast path. Otherwise a single
    /// [`FlatAttrs`] linear merge over the operands' symbol-sorted storage
    /// allocates with plain flat metadata. Both paths produce exactly the
    /// same attrset value bytes as the telemetry path in
    /// [`TreeWalk::merge_attr_update_entries`], which stays behind the
    /// [`Self::attr_update_telemetry_default`] toggle because its
    /// shape-census and representation-dispatch accounting re-walk every
    /// merge result.
    #[allow(clippy::too_many_arguments)]
    fn merge_attr_update_fast(
        &mut self,
        id: IrId,
        span: Span,
        lhs: IrId,
        lhs_span: Span,
        left: Value,
        rhs: IrId,
        rhs_span: Span,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        for (operand_id, operand_span, value) in [(lhs, lhs_span, left), (rhs, rhs_span, right)] {
            if value.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: operand_id,
                        expected: "attrs",
                        actual: value.tag(),
                    },
                    operand_span,
                ));
            }
        }
        let (merged, projected_shape) = {
            let left_attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, lhs_span)
            })?;
            let right_attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, rhs_span)
            })?;
            let same_keys = left_attrs
                .update_right_biased_same_keys(right_attrs)
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span)
                })?;
            match same_keys {
                Some(merged) => {
                    // The result's key set is exactly `left`'s, so `left`'s
                    // projected shape id describes the result verbatim.
                    // Propagate it only in record mode: the transient shaped
                    // select path is a measured net loss, so the baseline
                    // keeps merge results on the flat select path.
                    let projected_shape =
                        if self.options.attr_shape_mode() == AttrShapeMode::Record {
                            self.heap
                                .get_attrs_metadata(left)
                                .map_err(|source| {
                                    TreeWalkError::new(
                                        TreeWalkErrorKind::Heap { id, source },
                                        lhs_span,
                                    )
                                })?
                                .projected_shape()
                        } else {
                            None
                        };
                    (merged, projected_shape)
                }
                None => {
                    let merged = left_attrs
                        .update_right_biased(right_attrs, &self.symbols)
                        .map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span)
                        })?;
                    (merged, None)
                }
            }
        };
        self.heap
            .alloc_attrs_with_projected_shape_metadata(
                0,
                AttrSetReprKind::Flat,
                projected_shape,
                merged,
            )
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    /// Merges two already-forced attrset values using Nix `//` semantics.
    ///
    /// Callers own WHNF forcing and lazy-foldl normalization before entering
    /// this helper boundary; this routine checks both operand tags, performs a
    /// shallow right-biased merge, allocates the result, and records update
    /// telemetry.
    pub(crate) fn update_attr_values(
        &mut self,
        id: IrId,
        span: Span,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        self.update_attr_values_with_operand_metadata(id, span, id, span, left, id, span, right)
    }

    fn update_attr_values_with_operand_metadata(
        &mut self,
        id: IrId,
        span: Span,
        lhs: IrId,
        lhs_span: Span,
        left: Value,
        rhs: IrId,
        rhs_span: Span,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        if !self.attr_update_telemetry_enabled {
            return self.merge_attr_update_fast(id, span, lhs, lhs_span, left, rhs, rhs_span, right);
        }
        let left_operand = self.attr_entries_for_update(id, lhs, lhs_span, left)?;
        let right_operand = self.attr_entries_for_update(id, rhs, rhs_span, right)?;
        self.merge_attr_update_entries(id, span, lhs, left_operand, right_operand)
    }

    fn attr_entries_for_update(
        &self,
        id: IrId,
        operand_id: IrId,
        operand_span: Span,
        value: Value,
    ) -> Result<AttrUpdateOperand, TreeWalkError> {
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: operand_id,
                    expected: "attrs",
                    actual: value.tag(),
                },
                operand_span,
            ));
        }
        let metadata = self.heap.get_attrs_metadata(value).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, operand_span)
        })?;
        let attrs = self.heap.get_attrs(value).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, operand_span)
        })?;
        Ok(AttrUpdateOperand {
            entries: Self::clone_attr_entries(id, operand_span, attrs)?,
            metadata,
        })
    }

    fn merge_attr_update_entries(
        &mut self,
        id: IrId,
        span: Span,
        lhs: IrId,
        left_operand: AttrUpdateOperand,
        right_operand: AttrUpdateOperand,
    ) -> Result<Value, TreeWalkError> {
        let left_len = left_operand.entries.len();
        let right_len = right_operand.entries.len();
        let attrs = self.merge_flat_update_entries_for_active_heap(
            id,
            span,
            &left_operand.entries,
            &right_operand.entries,
        )?;
        let projection = self.project_attr_update_merge(
            id,
            span,
            lhs,
            left_operand.metadata.repr(),
            left_len,
            right_len,
        );
        let repr = projection.map_or(AttrSetReprKind::Flat, |projection| {
            projection.decision.kind()
        });
        let shape_telemetry = self.project_flat_attr_shape_telemetry(id, span, &attrs);
        let projected_shape = shape_telemetry.as_ref().map(|(shape, _)| shape.id());
        let result = self
            .heap
            .alloc_attrs_with_projected_shape_metadata(0, repr, projected_shape, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if let Some((census_shape, transitions)) = shape_telemetry {
            self.record_projected_attr_shape_telemetry(id, span, &census_shape, transitions);
        }

        if let Some(projection) = projection {
            match self.dispatch_attr_update_merge_for_telemetry(
                projection,
                &left_operand.entries,
                &right_operand.entries,
            ) {
                Ok(hamt_summary) => self.record_projected_attr_update_telemetry(
                    id,
                    span,
                    left_len,
                    right_len,
                    projection,
                    hamt_summary,
                ),
                Err(error) => {
                    tracing::debug!(
                        target: "aos_nix::eval::attr_telemetry",
                        node = id.as_u32(),
                        span_start = span.start,
                        span_end = span.end,
                        error = %error,
                        "skipping policy-dispatched attr update accounting after representation merge failure"
                    );
                }
            }
        }
        Ok(result)
    }

    fn merge_flat_update_entries_for_active_heap(
        &self,
        id: IrId,
        span: Span,
        left_entries: &[AttrEntry],
        right_entries: &[AttrEntry],
    ) -> Result<FlatAttrs, TreeWalkError> {
        let capacity = left_entries
            .len()
            .checked_add(right_entries.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::TooManyEntries { len: usize::MAX },
                    },
                    span,
                )
            })?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: capacity },
                },
                span,
            )
        })?;
        for entry in left_entries {
            if !right_entries.iter().any(|right| right.key == entry.key) {
                entries.push(*entry);
            }
        }
        entries.extend_from_slice(right_entries);

        FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))
    }

    fn dispatch_attr_update_merge_for_telemetry(
        &self,
        projection: AttrUpdateMergeProjection,
        left_entries: &[AttrEntry],
        right_entries: &[AttrEntry],
    ) -> Result<Option<HamtMergeSummary>, AttrUpdateTelemetryDispatchError> {
        let left_attrs = self.flat_attrs_from_update_entries_for_telemetry(left_entries)?;
        let right_attrs = self.flat_attrs_from_update_entries_for_telemetry(right_entries)?;
        let left = match projection.left_repr {
            AttrSetReprKind::Flat => AttrSetReprValue::from_flat(left_attrs),
            AttrSetReprKind::Hamt => AttrSetReprValue::from_hamt(
                HamtAttrs::from_flat(&left_attrs, &self.symbols)
                    .map_err(AttrUpdateTelemetryDispatchError::Hamt)?,
            ),
        };
        let merge = left
            .update_from_flat_right(
                &right_attrs,
                AttrSetReprPolicy::default(),
                projection.override_chain_depth,
                &self.symbols,
            )
            .map_err(AttrUpdateTelemetryDispatchError::Repr)?;
        debug_assert_eq!(merge.decision(), projection.decision);
        Ok(merge.hamt_summary())
    }

    fn flat_attrs_from_update_entries_for_telemetry(
        &self,
        entries: &[AttrEntry],
    ) -> Result<FlatAttrs, AttrUpdateTelemetryDispatchError> {
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(entries.len()).map_err(|_| {
            AttrUpdateTelemetryDispatchError::Flat(AttrError::AllocationFailed {
                entries: entries.len(),
            })
        })?;
        cloned.extend_from_slice(entries);
        FlatAttrs::new(cloned, &self.symbols).map_err(AttrUpdateTelemetryDispatchError::Flat)
    }

    pub(in crate::eval::tree_walk) fn concat_lists(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let concatenated = {
            let left = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            let right = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            left.concat(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::List { id, source }, node.span)
            })?
        };
        self.alloc_tree_walk_list(id, node.span, concatenated)
    }

    pub(in crate::eval::tree_walk) fn eval_comparison(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        match op {
            ComparisonOp::Lt => self.eval_less_than_comparison(id, node, lhs, rhs, false, lhs, rhs),
            ComparisonOp::Gt => self.eval_less_than_comparison(id, node, rhs, lhs, false, lhs, rhs),
            ComparisonOp::Le => self.eval_less_than_comparison(id, node, rhs, lhs, true, lhs, rhs),
            ComparisonOp::Ge => self.eval_less_than_comparison(id, node, lhs, rhs, true, lhs, rhs),
        }
    }

    pub(in crate::eval::tree_walk) fn eval_less_than_comparison(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
        invert: bool,
        source_lhs: IrId,
        source_rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let source_lhs_span = self.node(source_lhs)?.span;
        let source_rhs_span = self.node(source_rhs)?.span;
        let value = self.eval_comparison_values(
            id,
            node,
            ComparisonOp::Lt,
            lhs,
            lhs_span,
            left,
            rhs,
            rhs_span,
            right,
            source_lhs_span,
            source_rhs_span,
        )?;
        if invert {
            Ok(Value::bool(!self.expect_bool(id, value, node.span)?))
        } else {
            Ok(value)
        }
    }
}
