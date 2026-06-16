//! Safe tree-walk evaluator over lowered IR.
//!
//! The tree-walk evaluator is the permanent Phase-1 correctness oracle. These
//! first slices evaluate scalar and empty list literals, boolean control flow,
//! assertions, boolean operators, string literals and concatenation, list-spine
//! concatenation, numeric arithmetic, numeric and string comparisons, and
//! scalar/string equality to weak head normal form, establishing the arena
//! access and diagnostic surface used by later slices for environments, thunks,
//! functions, attribute sets, primitive operations, and derivation boundaries.

use thiserror::Error;

use super::heap::{EvalHeap, EvalHeapError};
use crate::compile::{Ir, IrChildSlice, IrData, IrId, IrKind, IrNode};
use crate::list::{NixList, NixListError};
use crate::string::{NixString, NixStringError};
use crate::syntax::{BinOpKind, Span, Symbol, UnaryOpKind};
use crate::value::{Value, ValueTag};

/// Evaluates an IR root to weak head normal form with the tree-walk oracle.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned`] for those values so their
/// evaluator heap stays alive.
pub fn eval_whnf(ir: &Ir) -> Result<Value, TreeWalkError> {
    let outcome = eval_whnf_owned(ir)?;
    if outcome.value.tag().is_heap() {
        let span = ir
            .arena
            .node(ir.root)
            .map(|node| node.span)
            .unwrap_or_default();
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: outcome.value.tag(),
            },
            span,
        ));
    }
    Ok(outcome.value)
}

/// Evaluates an IR root while returning the heap that owns heap-backed values.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned(ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
    let mut evaluator = TreeWalk::new(ir);
    let value = evaluator.eval_root()?;
    Ok(EvalOutcome {
        value,
        heap: evaluator.heap,
    })
}

/// A tree-walk evaluation result with its owning evaluator heap.
#[derive(Debug)]
pub struct EvalOutcome {
    value: Value,
    heap: EvalHeap,
}

impl EvalOutcome {
    /// Returns the evaluated root value.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the heap that owns heap-backed values in this result.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Consumes the outcome into its value and heap.
    pub fn into_parts(self) -> (Value, EvalHeap) {
        (self.value, self.heap)
    }
}

/// A safe recursive evaluator for lowered IR.
#[derive(Debug)]
pub struct TreeWalk<'ir> {
    ir: &'ir Ir,
    heap: EvalHeap,
}

impl<'ir> TreeWalk<'ir> {
    /// Creates a tree-walk evaluator over `ir`.
    pub const fn new(ir: &'ir Ir) -> Self {
        Self {
            ir,
            heap: EvalHeap::new(),
        }
    }

    /// Returns the evaluator heap that owns heap-backed values.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Evaluates the IR root to weak head normal form.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if evaluation of the root node fails.
    pub fn eval_root(&mut self) -> Result<Value, TreeWalkError> {
        self.eval_node(self.ir.root)
    }

    /// Evaluates a node to weak head normal form.
    ///
    /// This initial public node entry point is intentionally limited to
    /// environment-free scalar literal, empty list literal, string literal,
    /// control-flow, boolean operator, string/list concatenation, numeric
    /// arithmetic, numeric and string comparison, and scalar/string equality nodes.
    /// Environment-dependent nodes return
    /// [`TreeWalkErrorKind::UnsupportedNode`] until later slices add an explicit
    /// runtime and environment context.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if `id` does not address a node in this IR, if
    /// the node payload does not match its kind, if a scalar type check fails,
    /// or if the node kind is not yet implemented by this evaluator slice.
    pub fn eval_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        match node.kind {
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
            IrKind::Str => self.eval_string(id, &node),
            IrKind::List => self.eval_list(id, &node),
            IrKind::If => self.eval_if(id, &node),
            IrKind::Assert => self.eval_assert(id, &node),
            IrKind::UnaryOp => self.eval_unary(id, &node),
            IrKind::BinOp => self.eval_binary(id, &node),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedNode { id, kind },
                node.span,
            )),
        }
    }

    fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.ir.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    fn invalid_payload(&self, id: IrId, node: &IrNode, expected: &'static str) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::InvalidPayload {
                id,
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }

    fn eval_if(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "if payload"));
        };
        let selected = if self.eval_bool_node(first)? {
            second
        } else {
            third
        };
        self.eval_node(selected)
    }

    fn eval_assert(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair { first, second } = node.data else {
            return Err(self.invalid_payload(id, node, "assert payload"));
        };
        if self.eval_bool_node(first)? {
            self.eval_node(second)
        } else {
            Err(TreeWalkError::new(
                TreeWalkErrorKind::AssertionFailed { id },
                node.span,
            ))
        }
    }

    fn eval_unary(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Unary { op, operand } = node.data else {
            return Err(self.invalid_payload(id, node, "unary payload"));
        };
        match op {
            UnaryOpKind::Not => Ok(Value::bool(!self.eval_bool_node(operand)?)),
            UnaryOpKind::Neg => self.eval_numeric_negation(id, node, operand),
        }
    }

    fn eval_binary(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Binary { op, lhs, rhs } = node.data else {
            return Err(self.invalid_payload(id, node, "binary payload"));
        };
        match op {
            BinOpKind::And => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                } else {
                    Ok(Value::bool(false))
                }
            }
            BinOpKind::Or => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(true))
                } else {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                }
            }
            BinOpKind::Impl => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                } else {
                    Ok(Value::bool(true))
                }
            }
            BinOpKind::Add => self.eval_add(id, node, lhs, rhs),
            BinOpKind::Sub => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Sub, lhs, rhs),
            BinOpKind::Mul => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Mul, lhs, rhs),
            BinOpKind::Div => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Div, lhs, rhs),
            BinOpKind::Lt => self.eval_comparison(id, node, ComparisonOp::Lt, lhs, rhs),
            BinOpKind::Gt => self.eval_comparison(id, node, ComparisonOp::Gt, lhs, rhs),
            BinOpKind::Le => self.eval_comparison(id, node, ComparisonOp::Le, lhs, rhs),
            BinOpKind::Ge => self.eval_comparison(id, node, ComparisonOp::Ge, lhs, rhs),
            BinOpKind::Eq => self.eval_equality(id, node, lhs, rhs, false),
            BinOpKind::Ne => self.eval_equality(id, node, lhs, rhs, true),
            BinOpKind::Concat => self.eval_list_concat(id, node, lhs, rhs),
            BinOpKind::Update | BinOpKind::PipeRight | BinOpKind::PipeLeft => Err(
                TreeWalkError::new(TreeWalkErrorKind::UnsupportedBinaryOp { id, op }, node.span),
            ),
        }
    }

    fn eval_string(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "string symbol payload"));
        };
        let bytes = self.ir.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                node.span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.heap
            .alloc_string(NixString::from_bytes(owned))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_list(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Children(children) = node.data else {
            return Err(self.invalid_payload(id, node, "list children"));
        };
        let children = self.ir.arena.child_slice(children).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidChildSlice {
                    id,
                    slice: children,
                },
                node.span,
            )
        })?;
        if !children.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedListElements {
                    id,
                    len: children.len(),
                },
                node.span,
            ));
        }
        self.heap
            .alloc_list(NixList::empty())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_add(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                let left = self.expect_number(lhs, left, lhs_span)?;
                let right = self.expect_number(rhs, right, rhs_span)?;
                self.eval_numeric_values(id, node, BinaryArithmeticOp::Add, left, right)
            }
            ValueTag::String => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "string",
                            actual: right.tag(),
                        },
                        rhs_span,
                    ));
                }
                self.concat_strings(id, node, left, right)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number or string",
                    actual,
                },
                lhs_span,
            )),
        }
    }

    fn eval_equality(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
        invert: bool,
    ) -> Result<Value, TreeWalkError> {
        let left = self.eval_node(lhs)?;
        let right = self.eval_node(rhs)?;
        let equal = self.scalar_equal(id, node, left, right)?;
        Ok(Value::bool(if invert { !equal } else { equal }))
    }

    fn scalar_equal(
        &self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        match (left.tag(), right.tag()) {
            (ValueTag::Int, ValueTag::Int) => {
                Ok((left.payload_bits() as i64) == (right.payload_bits() as i64))
            }
            (ValueTag::Float, ValueTag::Float) => {
                Ok(f64::from_bits(left.payload_bits()) == f64::from_bits(right.payload_bits()))
            }
            (ValueTag::Int, ValueTag::Float) => {
                Ok((left.payload_bits() as i64) as f64 == f64::from_bits(right.payload_bits()))
            }
            (ValueTag::Float, ValueTag::Int) => {
                Ok(f64::from_bits(left.payload_bits()) == (right.payload_bits() as i64) as f64)
            }
            (ValueTag::Bool, ValueTag::Bool) => Ok(left.payload_bits() == right.payload_bits()),
            (ValueTag::Null, ValueTag::Null) => Ok(true),
            (ValueTag::String, ValueTag::String) => self.strings_equal(id, node, left, right),
            (left_tag, right_tag) if left_tag == right_tag => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedEqualityType {
                    id,
                    left: left_tag,
                    right: right_tag,
                },
                node.span,
            )),
            _ => Ok(false),
        }
    }

    fn strings_equal(
        &self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left = self.heap.get_string(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_string(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(left.bytes() == right.bytes())
    }

    fn eval_numeric_negation(
        &mut self,
        id: IrId,
        node: &IrNode,
        operand: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_number_node(operand)? {
            Number::Int(value) => value.checked_neg().map(Value::int).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ArithmeticOverflow {
                        id,
                        op: ArithmeticOp::Neg,
                    },
                    node.span,
                )
            }),
            Number::Float(value) => Ok(Value::float(-value)),
        }
    }

    fn eval_numeric_binary(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left = self.eval_number_node(lhs)?;
        let right = self.eval_number_node(rhs)?;
        self.eval_numeric_values(id, node, op, left, right)
    }

    fn eval_numeric_values(
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

    fn concat_strings(
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

    fn eval_list_concat(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
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

    fn concat_lists(
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

    fn eval_comparison(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                let left = self.expect_number(lhs, left, lhs_span)?;
                let right = self.expect_number(rhs, right, rhs_span)?;
                Ok(Value::bool(compare_numbers(op, left, right)))
            }
            ValueTag::String => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "string",
                            actual: right.tag(),
                        },
                        rhs_span,
                    ));
                }
                self.compare_strings(id, node, op, left, right)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number or string",
                    actual,
                },
                lhs_span,
            )),
        }
    }

    fn compare_strings(
        &self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let left = self.heap.get_string(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_string(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(Value::bool(op.compare_bytes(left.bytes(), right.bytes())))
    }

    fn eval_integer_binary(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: i64,
        right: i64,
    ) -> Result<Value, TreeWalkError> {
        let value = match op {
            BinaryArithmeticOp::Add => left.checked_add(right),
            BinaryArithmeticOp::Sub => left.checked_sub(right),
            BinaryArithmeticOp::Mul => left.checked_mul(right),
            BinaryArithmeticOp::Div => {
                if right == 0 {
                    return Err(self.division_by_zero(id, node));
                }
                left.checked_div(right)
            }
        };
        value.map(Value::int).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ArithmeticOverflow {
                    id,
                    op: op.into_arithmetic_op(),
                },
                node.span,
            )
        })
    }

    fn eval_float_binary(
        &self,
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
        Ok(Value::float(value))
    }

    fn division_by_zero(&self, id: IrId, node: &IrNode) -> TreeWalkError {
        TreeWalkError::new(TreeWalkErrorKind::DivisionByZero { id }, node.span)
    }

    fn eval_bool_node(&mut self, id: IrId) -> Result<bool, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_bool(id, value, span)
    }

    fn eval_number_node(&mut self, id: IrId) -> Result<Number, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_number(id, value, span)
    }

    fn expect_bool(&self, id: IrId, value: Value, span: Span) -> Result<bool, TreeWalkError> {
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
        match value.payload_bits() {
            0 => Ok(false),
            1 => Ok(true),
            payload => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidBoolPayload { id, payload },
                span,
            )),
        }
    }

    fn expect_number(&self, id: IrId, value: Value, span: Span) -> Result<Number, TreeWalkError> {
        match value.tag() {
            ValueTag::Int => Ok(Number::Int(value.payload_bits() as i64)),
            ValueTag::Float => Ok(Number::Float(f64::from_bits(value.payload_bits()))),
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
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Number {
    Int(i64),
    Float(f64),
}

impl Number {
    fn to_float(self) -> f64 {
        match self {
            Self::Int(value) => value as f64,
            Self::Float(value) => value,
        }
    }
}

fn compare_numbers(op: ComparisonOp, left: Number, right: Number) -> bool {
    match (left, right) {
        (Number::Int(left), Number::Int(right)) => op.compare_ints(left, right),
        (left, right) => op.compare_floats(left.to_float(), right.to_float()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BinaryArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
}

impl BinaryArithmeticOp {
    fn into_arithmetic_op(self) -> ArithmeticOp {
        match self {
            Self::Add => ArithmeticOp::Add,
            Self::Sub => ArithmeticOp::Sub,
            Self::Mul => ArithmeticOp::Mul,
            Self::Div => ArithmeticOp::Div,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComparisonOp {
    Lt,
    Gt,
    Le,
    Ge,
}

impl ComparisonOp {
    const fn compare_ints(self, left: i64, right: i64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    fn compare_floats(self, left: f64, right: f64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    fn compare_bytes(self, left: &[u8], right: &[u8]) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }
}

/// A numeric arithmetic operator used in tree-walk diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithmeticOp {
    /// Unary numeric negation.
    Neg,
    /// Binary numeric addition.
    Add,
    /// Binary numeric subtraction.
    Sub,
    /// Binary numeric multiplication.
    Mul,
    /// Binary numeric division.
    Div,
}

/// A tree-walk evaluation failure with source location.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct TreeWalkError {
    kind: TreeWalkErrorKind,
    span: Span,
}

impl TreeWalkError {
    /// Creates a tree-walk evaluation error.
    pub const fn new(kind: TreeWalkErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub fn kind(&self) -> TreeWalkErrorKind {
        self.kind.clone()
    }

    /// Returns the source span associated with this error.
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// The category of a tree-walk evaluation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkErrorKind {
    /// The evaluator was asked to read a missing IR node.
    #[error("invalid IR node id {id:?}")]
    InvalidNodeId {
        /// The missing node id.
        id: IrId,
    },
    /// The node kind and node payload disagreed.
    #[error("invalid payload for {kind:?} node {id:?}; expected {expected}")]
    InvalidPayload {
        /// The malformed node id.
        id: IrId,
        /// The node kind whose payload was malformed.
        kind: IrKind,
        /// The expected payload contract.
        expected: &'static str,
    },
    /// A child-pool slice payload did not resolve through the IR arena.
    #[error("invalid child slice {slice:?} at node {id:?}")]
    InvalidChildSlice {
        /// The node id carrying the invalid child slice.
        id: IrId,
        /// The invalid child slice payload.
        slice: IrChildSlice,
    },
    /// A symbol payload did not resolve through the IR symbol table.
    #[error("invalid symbol {symbol:?} at node {id:?}")]
    InvalidSymbol {
        /// The node id associated with the missing symbol.
        id: IrId,
        /// The unresolved symbol payload.
        symbol: Symbol,
    },
    /// A byte buffer for a string literal could not be reserved.
    #[error("failed to reserve {len} string bytes at node {id:?}")]
    ByteAllocationFailed {
        /// The string node id.
        id: IrId,
        /// The requested byte length.
        len: usize,
    },
    /// A heap-backed value was produced by the non-owning convenience API.
    #[error("heap-backed {tag:?} value at node {id:?} requires an owning evaluation result")]
    HeapValueRequiresOwner {
        /// The root node id that produced the heap value.
        id: IrId,
        /// The heap-backed value tag.
        tag: ValueTag,
    },
    /// The evaluator heap failed while allocating or retrieving a value.
    #[error("heap operation failed at node {id:?}: {source}")]
    Heap {
        /// The node id associated with the heap operation.
        id: IrId,
        /// The underlying heap failure.
        source: EvalHeapError,
    },
    /// A Nix string operation failed.
    #[error("string operation failed at node {id:?}: {source}")]
    String {
        /// The node id associated with the string operation.
        id: IrId,
        /// The underlying string failure.
        source: NixStringError,
    },
    /// A Nix list operation failed.
    #[error("list operation failed at node {id:?}: {source}")]
    List {
        /// The node id associated with the list operation.
        id: IrId,
        /// The underlying list failure.
        source: NixListError,
    },
    /// A scalar operation received a value of the wrong Nix type.
    #[error("type error at node {id:?}: expected {expected}, got {actual:?}")]
    Type {
        /// The node id associated with the type check.
        id: IrId,
        /// The expected evaluator value category.
        expected: &'static str,
        /// The actual runtime value tag.
        actual: ValueTag,
    },
    /// A boolean-tagged value had an invalid payload.
    ///
    /// Current safe constructors cannot create this state; the check is a
    /// defensive guard for later runtime fast paths and heap-backed values.
    #[error("invalid boolean payload {payload} at node {id:?}")]
    InvalidBoolPayload {
        /// The node id associated with the invalid payload.
        id: IrId,
        /// The invalid boolean payload.
        payload: u64,
    },
    /// The binary operator is outside this evaluator slice.
    #[error("unsupported tree-walk binary operator {op:?} at {id:?}")]
    UnsupportedBinaryOp {
        /// The unsupported node id.
        id: IrId,
        /// The unsupported binary operator.
        op: BinOpKind,
    },
    /// Structural equality for this runtime value type is outside this evaluator slice.
    #[error("unsupported tree-walk equality between {left:?} and {right:?} at {id:?}")]
    UnsupportedEqualityType {
        /// The equality operator node id.
        id: IrId,
        /// The left operand's runtime value tag.
        left: ValueTag,
        /// The right operand's runtime value tag.
        right: ValueTag,
    },
    /// Non-empty list spines require thunk allocation support.
    #[error("unsupported tree-walk non-empty list with {len} elements at {id:?}")]
    UnsupportedListElements {
        /// The list node id.
        id: IrId,
        /// The number of list elements in the spine.
        len: usize,
    },
    /// A checked integer arithmetic operation overflowed.
    #[error("arithmetic overflow for {op:?} at node {id:?}")]
    ArithmeticOverflow {
        /// The node id of the overflowing operator.
        id: IrId,
        /// The overflowing arithmetic operator.
        op: ArithmeticOp,
    },
    /// A numeric division operation used a zero divisor.
    #[error("division by zero at node {id:?}")]
    DivisionByZero {
        /// The division node id.
        id: IrId,
    },
    /// An `assert` condition evaluated to `false`.
    #[error("assertion failed at node {id:?}")]
    AssertionFailed {
        /// The failed assertion node id.
        id: IrId,
    },
    /// The node kind is outside this evaluator slice.
    #[error("unsupported tree-walk node {kind:?} at {id:?}")]
    UnsupportedNode {
        /// The unsupported node id.
        id: IrId,
        /// The unsupported node kind.
        kind: IrKind,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;

    use crate::compile::{
        EffectClass, IrArena, IrData, IrNode, lower as lower_ir, resolve as resolve_ast,
    };
    use crate::string::{ContextElement, StringContext};
    use crate::syntax::{Symbol, SymbolTable, parse_str};
    use crate::value::HeapObject;

    fn lower(source: &str) -> Ir {
        lower_ir(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    fn eval(source: &str) -> Value {
        eval_whnf(&lower(source)).expect("source evaluates")
    }

    fn empty_ir(root: IrId, arena: IrArena) -> Ir {
        Ir {
            root,
            arena,
            symbols: SymbolTable::new(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
    }

    fn pure_node(kind: IrKind, span: Span, data: IrData) -> IrNode {
        IrNode::new(kind, span, EffectClass::Pure, data)
    }

    fn manual_ir(root: IrId, nodes: Vec<IrNode>) -> Ir {
        empty_ir(root, IrArena::from_raw_parts(nodes, Vec::new()))
    }

    fn int_binary_ir(op: BinOpKind, left: i64, right: i64) -> Ir {
        let lhs = IrId::new(0);
        let rhs = IrId::new(1);
        let root = IrId::new(2);
        manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(left)),
                pure_node(IrKind::Int, Span::new(2, 3), IrData::Int(right)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(0, 3),
                    IrData::Binary { op, lhs, rhs },
                ),
            ],
        )
    }

    #[test]
    fn evaluates_inline_scalar_literals() {
        assert_eq!(eval("42").as_int(), Ok(42));
        assert_eq!(eval("true").as_bool(), Ok(true));
        assert_eq!(eval("false").as_bool(), Ok(false));
        assert_eq!(eval("null").as_null(), Ok(()));

        let float = eval("1.25").as_float().expect("float value");
        assert_eq!(float.to_bits(), 1.25f64.to_bits());
    }

    #[test]
    fn evaluates_string_literals_with_owned_heap() {
        let ir = lower("\"hello\"");
        let outcome = eval_whnf_owned(&ir).expect("string evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(
            outcome
                .heap()
                .get_string(value)
                .expect("string is heap-owned")
                .bytes(),
            b"hello"
        );

        let empty = eval_whnf_owned(&lower("\"\"")).expect("empty string evaluates");
        assert_eq!(
            empty
                .heap()
                .get_string(empty.value())
                .expect("empty string is heap-owned")
                .bytes(),
            b""
        );

        let escaped =
            eval_whnf_owned(&lower("\"line\\n\\\"quoted\\\"\"")).expect("escaped string evaluates");
        assert_eq!(
            escaped
                .heap()
                .get_string(escaped.value())
                .expect("escaped string is heap-owned")
                .bytes(),
            b"line\n\"quoted\""
        );
    }

    #[test]
    fn evaluates_empty_list_literals_with_owned_heap() {
        let ir = lower("[]");
        let outcome = eval_whnf_owned(&ir).expect("empty list evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::List);
        assert!(
            outcome
                .heap()
                .get_list(value)
                .expect("list is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn non_empty_list_literals_wait_for_thunk_allocation() {
        let ir = lower("[ (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("non-empty list needs thunks");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedListElements {
                id: ir.root,
                len: 1,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn list_concat_concatenates_empty_lists() {
        let ir = lower("[] ++ []");
        let outcome = eval_whnf_owned(&ir).expect("list concat evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::List);
        assert!(
            outcome
                .heap()
                .get_list(value)
                .expect("concat result is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn list_concat_preserves_spine_values_without_forcing_elements() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let left_ptr = NonNull::new(8usize as *mut HeapObject).expect("non-null pointer");
        let right_ptr = NonNull::new(16usize as *mut HeapObject).expect("non-null pointer");
        let left_thunk = Value::thunk(left_ptr).expect("left thunk pointer is aligned");
        let right_thunk = Value::thunk(right_ptr).expect("right thunk pointer is aligned");
        let left = evaluator
            .heap
            .alloc_list(NixList::new(vec![Value::int(1), left_thunk]))
            .expect("left list allocates");
        let right = evaluator
            .heap
            .alloc_list(NixList::new(vec![right_thunk, Value::bool(true)]))
            .expect("right list allocates");

        let result = evaluator
            .concat_lists(ir.root, &node, left, right)
            .expect("lists concatenate");
        let list = evaluator
            .heap
            .get_list(result)
            .expect("result list is heap-owned");

        assert_eq!(list.len(), 4);
        assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
        assert!(list.get(1).expect("second").raw_eq(left_thunk));
        assert!(list.get(2).expect("third").raw_eq(right_thunk));
        assert_eq!(list.get(3).expect("fourth").as_bool(), Ok(true));
    }

    #[test]
    fn list_concat_type_checks_operands_left_to_right() {
        let lhs_ir = lower("1 ++ (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("concat root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let rhs_ir = lower("[] ++ 1");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("concat root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let rhs_error_ir = lower("[] ++ (1 / 0)");
        let root = rhs_error_ir
            .arena
            .node(rhs_error_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("concat root has binary payload");
        };
        let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn non_owning_eval_rejects_list_concat_heap_values() {
        let ir = lower("[] ++ []");
        let error = eval_whnf(&ir).expect_err("list concat value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::List,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn string_add_concatenates_heap_strings() {
        let outcome = eval_whnf_owned(&lower("\"a\" + \"b\"")).expect("string add evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(
            outcome
                .heap()
                .get_string(value)
                .expect("string add result is heap-owned")
                .bytes(),
            b"ab"
        );

        let escaped =
            eval_whnf_owned(&lower("\"a\\n\" + \"b\"")).expect("escaped string add evaluates");
        assert_eq!(
            escaped
                .heap()
                .get_string(escaped.value())
                .expect("escaped add result is heap-owned")
                .bytes(),
            b"a\nb"
        );
    }

    #[test]
    fn string_add_unions_contexts() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let output =
            ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
                .expect("output context is valid");
        let left = evaluator
            .heap
            .alloc_string(NixString::new(
                b"hello".to_vec(),
                StringContext::singleton(source.clone()).expect("source context allocates"),
            ))
            .expect("left string allocates");
        let right = evaluator
            .heap
            .alloc_string(NixString::new(
                b" world".to_vec(),
                StringContext::singleton(output.clone()).expect("output context allocates"),
            ))
            .expect("right string allocates");

        let result = evaluator
            .concat_strings(ir.root, &node, left, right)
            .expect("strings concatenate");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result string is heap-owned");

        assert_eq!(string.bytes(), b"hello world");
        assert_eq!(string.context().len(), 2);
        assert!(string.context().contains(&source));
        assert!(string.context().contains(&output));
    }

    #[test]
    fn string_add_rejects_non_string_rhs() {
        let ir = lower("\"a\" + 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn string_add_evaluates_rhs_before_type_checking_it() {
        let ir = lower("\"a\" + (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn numeric_add_rejects_string_rhs_as_non_numeric() {
        let ir = lower("1 + \"a\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("string rhs is invalid for numeric add");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn non_owning_eval_rejects_string_add_heap_values() {
        let ir = lower("\"a\" + \"b\"");
        let error = eval_whnf(&ir).expect_err("string add value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::String,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn non_owning_eval_rejects_heap_values() {
        let ir = lower("\"hello\"");
        let error = eval_whnf(&ir).expect_err("string value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::String,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let list_ir = lower("[]");
        let error = eval_whnf(&list_ir).expect_err("list value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: list_ir.root,
                tag: ValueTag::List,
            }
        );
        assert_eq!(
            error.span(),
            list_ir.arena.node(list_ir.root).expect("root exists").span
        );
    }

    #[test]
    fn unsupported_nodes_report_kind_and_span() {
        let ir = lower("{}");
        let error = eval_whnf(&ir).expect_err("attrset construction is not implemented yet");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedNode {
                id: ir.root,
                kind: IrKind::AttrSet,
            }
        );
        assert_eq!(error.span(), Span::new(0, 2));
    }

    #[test]
    fn unsupported_operators_report_operator_and_span() {
        let binary = lower("1 // 2");
        let binary_error =
            eval_whnf(&binary).expect_err("attribute-set update is not implemented yet");
        assert_eq!(
            binary_error.kind(),
            TreeWalkErrorKind::UnsupportedBinaryOp {
                id: binary.root,
                op: BinOpKind::Update,
            }
        );
        assert_eq!(
            binary_error.span(),
            binary.arena.node(binary.root).expect("root exists").span
        );
    }

    #[test]
    fn invalid_node_ids_are_reported() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let missing = IrId::new(99);
        let error = evaluator
            .eval_node(missing)
            .expect_err("missing node is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidNodeId { id: missing }
        );
        assert_eq!(error.span(), Span::default());
    }

    #[test]
    fn malformed_literal_payloads_are_reported() {
        let cases = [
            (IrKind::Int, IrData::None, "integer payload"),
            (IrKind::Float, IrData::None, "float payload"),
            (IrKind::Bool, IrData::None, "boolean payload"),
            (IrKind::Null, IrData::Bool(false), "empty payload"),
            (IrKind::Str, IrData::None, "string symbol payload"),
            (IrKind::List, IrData::None, "list children"),
        ];

        for (index, (kind, data, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(index as u32, index as u32 + 1);
            let arena = IrArena::from_raw_parts(
                vec![IrNode::new(kind, span, EffectClass::Pure, data)],
                Vec::new(),
            );
            let ir = empty_ir(root, arena);
            let error = eval_whnf(&ir).expect_err("malformed literal is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn invalid_string_symbols_are_reported() {
        let root = IrId::new(0);
        let symbol = Symbol::new(99);
        let span = Span::new(3, 8);
        let ir = manual_ir(
            root,
            vec![pure_node(IrKind::Str, span, IrData::Symbol(symbol))],
        );
        let error = eval_whnf_owned(&ir).expect_err("string symbol must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_list_child_slices_are_reported() {
        let root = IrId::new(0);
        let slice = IrChildSlice::new(7, 1);
        let span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![pure_node(IrKind::List, span, IrData::Children(slice))],
        );
        let error = eval_whnf_owned(&ir).expect_err("list child slice must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidChildSlice { id: root, slice }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn if_evaluates_only_the_selected_branch() {
        assert_eq!(eval("if true then 1 else 2").as_int(), Ok(1));
        assert_eq!(eval("if false then 1 else 2").as_int(), Ok(2));

        let lazy_else = eval("if true then 7 else (1 ++ 2)");
        assert_eq!(lazy_else.as_int(), Ok(7));

        let lazy_then = eval("if false then (1 ++ 2) else 9");
        assert_eq!(lazy_then.as_int(), Ok(9));
    }

    #[test]
    fn if_condition_must_be_bool() {
        let ir = lower("if 1 then 2 else 3");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Triple { first, .. } = root.data else {
            panic!("if root has triple payload");
        };
        let condition_span = ir.arena.node(first).expect("condition exists").span;

        let error = eval_whnf(&ir).expect_err("integer condition is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), condition_span);
    }

    #[test]
    fn malformed_if_payloads_are_reported() {
        let root = IrId::new(0);
        let span = Span::new(10, 12);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::If,
                span,
                EffectClass::Pure,
                IrData::None,
            )],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed if is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind: IrKind::If,
                expected: "if payload",
            }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn unary_not_evaluates_boolean_operands() {
        assert_eq!(eval("!true").as_bool(), Ok(false));
        assert_eq!(eval("!false").as_bool(), Ok(true));
    }

    #[test]
    fn unary_not_rejects_non_bool_operands() {
        let ir = lower("!1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Unary { operand, .. } = root.data else {
            panic!("not root has unary payload");
        };
        let operand_span = ir.arena.node(operand).expect("operand exists").span;

        let error = eval_whnf(&ir).expect_err("integer operand is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: operand,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), operand_span);
    }

    #[test]
    fn numeric_unary_negation_handles_ints_and_floats() {
        assert_eq!(eval("-1").as_int(), Ok(-1));
        assert_eq!(eval("-1.5").as_float(), Ok(-1.5));

        let operand = IrId::new(0);
        let root = IrId::new(1);
        let root_span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(1, 2), IrData::Int(i64::MIN)),
                pure_node(
                    IrKind::UnaryOp,
                    root_span,
                    IrData::Unary {
                        op: UnaryOpKind::Neg,
                        operand,
                    },
                ),
            ],
        );

        let error = eval_whnf(&ir).expect_err("negating i64::MIN overflows");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ArithmeticOverflow {
                id: root,
                op: ArithmeticOp::Neg,
            }
        );
        assert_eq!(error.span(), root_span);
    }

    #[test]
    fn numeric_unary_negation_rejects_non_numbers() {
        let ir = lower("-true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Unary { operand, .. } = root.data else {
            panic!("negation root has unary payload");
        };
        let operand_span = ir.arena.node(operand).expect("operand exists").span;

        let error = eval_whnf(&ir).expect_err("boolean negation operand is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: operand,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), operand_span);
    }

    #[test]
    fn numeric_arithmetic_handles_ints_and_float_promotion() {
        assert_eq!(eval("1 + 2").as_int(), Ok(3));
        assert_eq!(eval("5 - 8").as_int(), Ok(-3));
        assert_eq!(eval("2 * 3").as_int(), Ok(6));
        assert_eq!(eval("1 + 2.5").as_float(), Ok(3.5));
        assert_eq!(eval("2 * 0.5").as_float(), Ok(1.0));
    }

    #[test]
    fn integer_division_truncates_toward_zero() {
        assert_eq!(eval("7 / (-2)").as_int(), Ok(-3));
    }

    #[test]
    fn float_or_mixed_division_returns_float() {
        assert_eq!(eval("7 / 2.0").as_float(), Ok(3.5));
        assert_eq!(eval("7.0 / 2").as_float(), Ok(3.5));
    }

    #[test]
    fn division_by_zero_errors_at_operator_span() {
        let ir = lower("1 / 0");
        let error = eval_whnf(&ir).expect_err("integer division by zero is invalid");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: ir.root }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let float_ir = lower("1.0 / -0.0");
        let error = eval_whnf(&float_ir).expect_err("float division by zero is invalid");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: float_ir.root }
        );
        assert_eq!(
            error.span(),
            float_ir
                .arena
                .node(float_ir.root)
                .expect("root exists")
                .span
        );
    }

    #[test]
    fn integer_arithmetic_overflow_errors_at_operator_span() {
        let cases = [
            (BinOpKind::Add, i64::MAX, 1, ArithmeticOp::Add),
            (BinOpKind::Sub, i64::MIN, 1, ArithmeticOp::Sub),
            (BinOpKind::Mul, i64::MAX, 2, ArithmeticOp::Mul),
            (BinOpKind::Div, i64::MIN, -1, ArithmeticOp::Div),
        ];

        for (op, left, right, arithmetic_op) in cases {
            let ir = int_binary_ir(op, left, right);
            let root_span = ir.arena.node(ir.root).expect("root exists").span;
            let error = eval_whnf(&ir).expect_err("checked arithmetic overflows");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::ArithmeticOverflow {
                    id: ir.root,
                    op: arithmetic_op,
                }
            );
            assert_eq!(error.span(), root_span);
        }
    }

    #[test]
    fn numeric_operators_type_check_operands_left_to_right() {
        let rhs_ir = lower("1 + true");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let lhs_ir = lower("true - (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("subtraction root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("boolean lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn scalar_equality_handles_inline_values() {
        assert_eq!(eval("1 == 1").as_bool(), Ok(true));
        assert_eq!(eval("1 == 2").as_bool(), Ok(false));
        assert_eq!(eval("1 == 1.0").as_bool(), Ok(true));
        assert_eq!(eval("1 != 1.5").as_bool(), Ok(true));
        assert_eq!(eval("true == true").as_bool(), Ok(true));
        assert_eq!(eval("true != false").as_bool(), Ok(true));
        assert_eq!(eval("null == null").as_bool(), Ok(true));
        assert_eq!(eval("null == false").as_bool(), Ok(false));
        assert_eq!(eval("1 == true").as_bool(), Ok(false));
    }

    #[test]
    fn string_equality_compares_bytes() {
        assert_eq!(eval("\"a\" == \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" == \"b\"").as_bool(), Ok(false));
        assert_eq!(eval("\"a\" != \"b\"").as_bool(), Ok(true));
        assert_eq!(eval("\"line\\n\" == \"line\\n\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" == 1").as_bool(), Ok(false));
        assert_eq!(eval("1 != \"a\"").as_bool(), Ok(true));
    }

    #[test]
    fn string_equality_ignores_contexts() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let output =
            ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
                .expect("output context is valid");
        let left = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("left string allocates");
        let right = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(output).expect("output context allocates"),
            ))
            .expect("right string allocates");

        assert_eq!(
            evaluator
                .scalar_equal(ir.root, &node, left, right)
                .expect("strings compare"),
            true
        );
    }

    #[test]
    fn scalar_equality_evaluates_operands_left_to_right() {
        let rhs_ir = lower("false == (1 / 0)");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("equality root has binary payload");
        };
        let rhs_id = rhs;
        let rhs_span = rhs_ir.arena.node(rhs_id).expect("rhs exists").span;
        let error = eval_whnf(&rhs_ir).expect_err("rhs division by zero is evaluated");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: rhs_id }
        );
        assert_eq!(error.span(), rhs_span);

        let lhs_ir = lower("(1 / 0) == false");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("equality root has binary payload");
        };
        let lhs_id = lhs;
        let lhs_span = lhs_ir.arena.node(lhs_id).expect("lhs exists").span;
        let error = eval_whnf(&lhs_ir).expect_err("lhs division by zero is evaluated first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: lhs_id }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn non_string_heap_equality_is_unsupported_until_structural_equality_lands() {
        let ir = lower("1");
        let evaluator = TreeWalk::new(&ir);
        let node = ir.arena.node(ir.root).expect("root exists");
        let ptr = NonNull::<HeapObject>::dangling();
        let left = Value::list(ptr).expect("aligned list pointer");
        let right = Value::list(ptr).expect("aligned list pointer");

        let error = evaluator
            .scalar_equal(ir.root, node, left, right)
            .expect_err("list equality is not implemented yet");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedEqualityType {
                id: ir.root,
                left: ValueTag::List,
                right: ValueTag::List,
            }
        );
        assert_eq!(error.span(), node.span);
    }

    #[test]
    fn numeric_comparisons_handle_ints_floats_and_promotion() {
        assert_eq!(eval("1 < 2").as_bool(), Ok(true));
        assert_eq!(eval("2 > 1").as_bool(), Ok(true));
        assert_eq!(eval("2 <= 2").as_bool(), Ok(true));
        assert_eq!(eval("2 >= 3").as_bool(), Ok(false));
        assert_eq!(eval("1 < 1.5").as_bool(), Ok(true));
        assert_eq!(eval("1.5 >= 2").as_bool(), Ok(false));
    }

    #[test]
    fn string_comparisons_use_byte_order() {
        assert_eq!(eval("\"a\" < \"b\"").as_bool(), Ok(true));
        assert_eq!(eval("\"b\" > \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" <= \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" >= \"b\"").as_bool(), Ok(false));
        assert_eq!(eval("\"Z\" < \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\\n\" < \"aa\"").as_bool(), Ok(true));
    }

    #[test]
    fn string_comparisons_use_bytes_not_contexts() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let output =
            ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
                .expect("output context is valid");
        let left = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("left string allocates");
        let right = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(output).expect("output context allocates"),
            ))
            .expect("right string allocates");

        assert_eq!(
            evaluator
                .compare_strings(ir.root, &node, ComparisonOp::Le, left, right)
                .expect("strings compare")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            evaluator
                .compare_strings(ir.root, &node, ComparisonOp::Ge, left, right)
                .expect("strings compare")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            evaluator
                .compare_strings(ir.root, &node, ComparisonOp::Lt, left, right)
                .expect("strings compare")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn comparisons_type_check_operands_left_to_right() {
        let rhs_ir = lower("1 < true");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let string_rhs_ir = lower("1 < \"a\"");
        let root = string_rhs_ir
            .arena
            .node(string_rhs_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = string_rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&string_rhs_ir).expect_err("string rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let string_left_ir = lower("\"a\" < true");
        let root = string_left_ir
            .arena
            .node(string_left_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = string_left_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&string_left_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "string",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let rhs_error_ir = lower("\"a\" < (1 / 0)");
        let root = rhs_error_ir
            .arena
            .node(rhs_error_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let lhs_ir = lower("false < (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("boolean lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number or string",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn boolean_binary_operators_short_circuit() {
        assert_eq!(eval("true && true").as_bool(), Ok(true));
        assert_eq!(eval("true && false").as_bool(), Ok(false));
        assert_eq!(eval("false && (1 ++ 2)").as_bool(), Ok(false));

        assert_eq!(eval("true || (1 ++ 2)").as_bool(), Ok(true));
        assert_eq!(eval("false || true").as_bool(), Ok(true));
        assert_eq!(eval("false || false").as_bool(), Ok(false));

        assert_eq!(eval("false -> (1 ++ 2)").as_bool(), Ok(true));
        assert_eq!(eval("true -> true").as_bool(), Ok(true));
        assert_eq!(eval("true -> false").as_bool(), Ok(false));
    }

    #[test]
    fn boolean_binary_operators_type_check_evaluated_rhs() {
        let ir = lower("true && 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("and root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn malformed_operator_payloads_are_reported() {
        let cases = [
            (IrKind::UnaryOp, "unary payload"),
            (IrKind::BinOp, "binary payload"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(20 + index as u32, 21 + index as u32);
            let arena = IrArena::from_raw_parts(
                vec![IrNode::new(kind, span, EffectClass::Pure, IrData::None)],
                Vec::new(),
            );
            let ir = empty_ir(root, arena);
            let error = eval_whnf(&ir).expect_err("malformed operator is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn assert_evaluates_body_only_when_condition_is_true() {
        assert_eq!(eval("assert true; 5").as_int(), Ok(5));

        let ir = lower("assert false; (1 ++ 2)");
        let lazy_body = eval_whnf(&ir).expect_err("false assertion stops before body");
        assert_eq!(
            lazy_body.kind(),
            TreeWalkErrorKind::AssertionFailed { id: ir.root }
        );
    }

    #[test]
    fn assert_false_reports_assertion_span() {
        let ir = lower("assert false; 1");
        let error = eval_whnf(&ir).expect_err("assertion fails");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::AssertionFailed { id: ir.root }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn assert_condition_must_be_bool() {
        let ir = lower("assert 1; 2");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Pair { first, .. } = root.data else {
            panic!("assert root has pair payload");
        };
        let condition_span = ir.arena.node(first).expect("condition exists").span;

        let error = eval_whnf(&ir).expect_err("integer condition is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), condition_span);
    }

    #[test]
    fn malformed_assert_payloads_are_reported() {
        let root = IrId::new(0);
        let span = Span::new(30, 35);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Assert,
                span,
                EffectClass::Pure,
                IrData::None,
            )],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed assert is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind: IrKind::Assert,
                expected: "assert payload",
            }
        );
        assert_eq!(error.span(), span);
    }
}
