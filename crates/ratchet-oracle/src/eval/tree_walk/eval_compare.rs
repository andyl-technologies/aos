//! Comparison builtins, list comparison, and argument-expectation helpers.

use super::*;

impl TreeWalk {
    pub(super) fn eval_comparison_values(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        lhs: IrId,
        lhs_span: Span,
        left: Value,
        rhs: IrId,
        rhs_span: Span,
        right: Value,
        source_lhs_span: Span,
        source_rhs_span: Span,
    ) -> Result<Value, TreeWalkError> {
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let left = self.expect_number(lhs, left, lhs_span).map_err(|error| {
                    self.label_binary_operand_error(error, source_lhs_span, source_rhs_span)
                })?;
                let right = self.expect_number(rhs, right, rhs_span).map_err(|error| {
                    self.label_binary_operand_error(error, source_lhs_span, source_rhs_span)
                })?;
                Ok(Value::bool(compare_numbers(op, left, right)))
            }
            ValueTag::String => {
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "string",
                            actual: right.tag(),
                        },
                        rhs_span,
                    )
                    .with_label(source_lhs_span, "left operand")
                    .with_label(source_rhs_span, "right operand"));
                }
                self.compare_strings(id, node, op, left, right)
            }
            ValueTag::Path => {
                if right.tag() != ValueTag::Path {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "path",
                            actual: right.tag(),
                        },
                        rhs_span,
                    )
                    .with_label(source_lhs_span, "left operand")
                    .with_label(source_rhs_span, "right operand"));
                }
                self.compare_paths(id, node, op, left, right)
            }
            ValueTag::List => {
                if right.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "list",
                            actual: right.tag(),
                        },
                        rhs_span,
                    )
                    .with_label(source_lhs_span, "left operand")
                    .with_label(source_rhs_span, "right operand"));
                }
                self.compare_lists(id, node, op, left, right)
                    .map(Value::bool)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number, string, path, or list",
                    actual,
                },
                lhs_span,
            )
            .with_label(source_lhs_span, "left operand")
            .with_label(source_rhs_span, "right operand")),
        }
    }

    pub(super) fn compare_strings(
        &self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let left = self.heap.get_string_view(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_string_view(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(Value::bool(op.compare_bytes(left.bytes(), right.bytes())))
    }

    pub(super) fn compare_paths(
        &self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let left = self.heap.get_path_view(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_path_view(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(Value::bool(op.compare_bytes(left.bytes(), right.bytes())))
    }

    pub(super) fn compare_lists(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let mut equality_guard = EqualityPairGuard::default();
        self.compare_lists_with_guard(id, node, op, left, right, &mut equality_guard)
    }

    pub(super) fn compare_lists_with_guard(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        self.heap.observe_value_identity(left);
        self.heap.observe_value_identity(right);
        if !equality_guard.enter(left, right) {
            return Ok(op.compare_equal());
        }

        let result =
            self.compare_list_entries_with_guard(id, node, op, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    pub(super) fn compare_list_entries_with_guard(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list_view(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list_view(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };

        for (left, right) in left_elements
            .iter()
            .copied()
            .zip(right_elements.iter().copied())
        {
            if self.values_equal_for_ordering_nested_lazy(
                id,
                node,
                id,
                node.span,
                left,
                id,
                node.span,
                right,
                equality_guard,
            )? {
                continue;
            }
            let left = self.force_value(id, node.span, left)?;
            let right = self.force_value(id, node.span, right)?;
            return self.compare_values_for_ordering(id, node, op, left, right, equality_guard);
        }

        Ok(op.compare_lengths(left_elements.len(), right_elements.len()))
    }

    pub(super) fn compare_values_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let left = self.expect_number(id, left, node.span)?;
                let right = self.expect_number(id, right, node.span)?;
                Ok(compare_numbers(op, left, right))
            }
            ValueTag::String => {
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: right.tag(),
                        },
                        node.span,
                    ));
                }
                self.compare_strings(id, node, op, left, right)
                    .and_then(|value| self.expect_bool(id, value, node.span))
            }
            ValueTag::Path => {
                if right.tag() != ValueTag::Path {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "path",
                            actual: right.tag(),
                        },
                        node.span,
                    ));
                }
                self.compare_paths(id, node, op, left, right)
                    .and_then(|value| self.expect_bool(id, value, node.span))
            }
            ValueTag::List => {
                if right.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "list",
                            actual: right.tag(),
                        },
                        node.span,
                    ));
                }
                self.compare_lists_with_guard(id, node, op, left, right, equality_guard)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "number, string, path, or list",
                    actual,
                },
                node.span,
            )),
        }
    }

    pub(super) fn values_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        match (left.tag(), right.tag()) {
            (ValueTag::List, ValueTag::List) => {
                self.lists_equal_for_ordering(id, node, left, right, equality_guard)
            }
            (ValueTag::Attrs, ValueTag::Attrs) => {
                self.attrsets_equal_for_ordering(id, node, left, right, equality_guard)
            }
            _ => self.values_equal(id, node, left, right, EqualityContext::Nested),
        }
    }

    pub(super) fn values_equal_for_ordering_nested_lazy(
        &mut self,
        id: IrId,
        node: &IrNode,
        left_id: IrId,
        left_span: Span,
        left: Value,
        right_id: IrId,
        right_span: Span,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_identity = self.nested_identity_value(id, node.span, left)?;
        let right_identity = self.nested_identity_value(id, node.span, right)?;
        self.heap.observe_value_identity(left_identity);
        self.heap.observe_value_identity(right_identity);
        let shared_heap_identity =
            left_identity.raw_eq(right_identity) && left_identity.tag().is_heap();
        if shared_heap_identity && left_identity.tag() != ValueTag::Thunk {
            return Ok(true);
        }

        let left = self.force_value(left_id, left_span, left_identity)?;
        let right = self.force_value(right_id, right_span, right_identity)?;
        self.heap.observe_value_identity(left);
        self.heap.observe_value_identity(right);
        if shared_heap_identity
            && left.raw_eq(right)
            && left.tag().is_heap()
            && left.tag() != ValueTag::Thunk
        {
            return Ok(true);
        }
        if shared_heap_identity
            && left.tag() == ValueTag::Float
            && right.tag() == ValueTag::Float
            && self
                .heap
                .decode_float_value(left)
                .map(f64::is_nan)
                .unwrap_or(false)
            && self
                .heap
                .decode_float_value(right)
                .map(f64::is_nan)
                .unwrap_or(false)
        {
            return Ok(true);
        }
        self.values_equal_for_ordering(id, node, left, right, equality_guard)
    }

    pub(super) fn lists_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        self.heap.observe_value_identity(left);
        self.heap.observe_value_identity(right);
        if !equality_guard.enter(left, right) {
            return Ok(true);
        }

        let result = self.list_entries_equal_for_ordering(id, node, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    pub(super) fn list_entries_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list_view(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list_view(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        if left_elements.len() != right_elements.len() {
            return Ok(false);
        }

        for (left, right) in left_elements.into_iter().zip(right_elements) {
            if !self.values_equal_for_ordering_nested_lazy(
                id,
                node,
                id,
                node.span,
                left,
                id,
                node.span,
                right,
                equality_guard,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn attrsets_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        self.heap.observe_value_identity(left);
        self.heap.observe_value_identity(right);
        if !equality_guard.enter(left, right) {
            return Ok(true);
        }

        let result = self.attrset_entries_equal_for_ordering(id, node, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    pub(super) fn attrset_entries_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_entries = {
            let attrs = self.heap.get_attrs_view(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        let right_entries = {
            let attrs = self.heap.get_attrs_view(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        if left_entries.len() != right_entries.len() {
            return Ok(false);
        }

        for (left, right) in left_entries.iter().zip(&right_entries) {
            if left.key != right.key {
                return Ok(false);
            }
        }
        for (left, right) in left_entries.into_iter().zip(right_entries) {
            if !self.values_equal_for_ordering_nested_lazy(
                id,
                node,
                id,
                node.span,
                left.value,
                id,
                node.span,
                right.value,
                equality_guard,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn eval_integer_binary(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: i64,
        right: i64,
    ) -> Result<Value, TreeWalkError> {
        let value = match op {
            BinaryArithmeticOp::Add => left.wrapping_add(right),
            BinaryArithmeticOp::Sub => left.wrapping_sub(right),
            BinaryArithmeticOp::Mul => left.wrapping_mul(right),
            BinaryArithmeticOp::Div => {
                if right == 0 {
                    return Err(self.division_by_zero(id, node));
                }
                left.checked_div(right).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ArithmeticOverflow {
                            id,
                            op: ArithmeticOp::Div,
                        },
                        node.span,
                    )
                })?
            }
        };
        self.runtime_int_value(id, node.span, value)
    }

    pub(super) fn eval_float_binary(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: f64,
        right: f64,
    ) -> Result<Value, TreeWalkError> {
        let value = match op {
            BinaryArithmeticOp::Add => left + right,
            BinaryArithmeticOp::Sub => left - right,
            BinaryArithmeticOp::Mul => left * right,
            BinaryArithmeticOp::Div => {
                if right == 0.0 {
                    return Err(self.division_by_zero(id, node));
                }
                left / right
            }
        };
        self.runtime_float_value(id, node.span, value)
    }

    pub(super) fn division_by_zero(&self, id: IrId, node: &IrNode) -> TreeWalkError {
        TreeWalkError::new(TreeWalkErrorKind::DivisionByZero { id }, node.span)
    }

    pub(super) fn eval_bool_node(&mut self, id: IrId) -> Result<bool, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_bool(id, value, span)
    }

    pub(super) fn eval_number_node(&mut self, id: IrId) -> Result<Number, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        let value = self.force_demanded_value(id, span, value)?;
        self.expect_number(id, value, span)
    }

    pub(super) fn eval_int_node(&mut self, id: IrId) -> Result<i64, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_int(id, value, span)
    }

    pub(super) fn expect_bool(
        &self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<bool, TreeWalkError> {
        if value.tag() != ValueTag::Bool {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "bool",
                    actual: value.tag(),
                },
                span,
            ));
        }
        // Decode through the checked accessor rather than reading raw payload
        // bits: on the Candidate-C carrier the raw word is not the 0/1 boolean
        // payload (the tag occupies the high half), so a raw compare would reject
        // every boolean. `as_bool` is self-contained on both carriers.
        value.as_bool().map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidBoolPayload {
                    id,
                    payload: value.payload_bits(),
                },
                span,
            )
        })
    }

    pub(super) fn expect_number(
        &self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Number, TreeWalkError> {
        match value.tag() {
            ValueTag::Int => self.runtime_int_payload(id, span, value).map(Number::Int),
            ValueTag::Float => self
                .runtime_float_payload(id, span, value)
                .map(Number::Float),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "number",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn label_binary_operand_error(
        &self,
        error: TreeWalkError,
        lhs_span: Span,
        rhs_span: Span,
    ) -> TreeWalkError {
        error
            .with_label(lhs_span, "left operand")
            .with_label(rhs_span, "right operand")
    }

    pub(super) fn expect_int(
        &self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<i64, TreeWalkError> {
        if value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "int",
                    actual: value.tag(),
                },
                span,
            ));
        }
        self.runtime_int_payload(id, span, value)
    }
}
