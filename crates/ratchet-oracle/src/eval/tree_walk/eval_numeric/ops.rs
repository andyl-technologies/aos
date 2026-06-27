//! Numeric, concatenation, update, and comparison operator helpers.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_numeric_negation(
        &mut self,
        _id: IrId,
        _node: &IrNode,
        operand: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_number_node(operand)? {
            Number::Int(value) => Ok(Value::int(value.wrapping_neg())),
            Number::Float(value) => Ok(Value::float(-value)),
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
        self.heap
            .alloc_string(concatenated)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
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
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, lhs_span)
            })?;
            Self::clone_attr_entries(id, lhs_span, attrs)?
        };

        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_lazy_foldl_initial_value(rhs, rhs_span, right)?;
        if right.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: rhs,
                    expected: "attrs",
                    actual: right.tag(),
                },
                rhs_span,
            ));
        }
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, rhs_span)
            })?;
            Self::clone_attr_entries(id, rhs_span, attrs)?
        };

        let capacity = left_entries
            .len()
            .checked_add(right_entries.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::TooManyEntries { len: usize::MAX },
                    },
                    node.span,
                )
            })?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: capacity },
                },
                node.span,
            )
        })?;
        for entry in left_entries {
            if !right_entries.iter().any(|right| right.key == entry.key) {
                entries.push(entry);
            }
        }
        entries.extend(right_entries);

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
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
        self.heap
            .alloc_list(concatenated)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
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
