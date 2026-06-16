//! Safe tree-walk evaluator over lowered IR.
//!
//! The tree-walk evaluator is the permanent Phase-1 correctness oracle. These
//! first slices evaluate scalar and list literals, boolean control flow,
//! assertions, boolean operators, string/URI literals and concatenation, list-spine
//! concatenation, static and recursive static attribute-set literals, dynamic
//! string-valued attribute names, static and dynamic string-valued
//! attribute selection, lexical `let` environments, simple and formal-set lambda
//! application, lazy `with` scope lookup, attrset update, thunk forcing, numeric
//! arithmetic, numeric and string/list comparisons, direct strict primops,
//! and scalar/string/function plus structural
//! list/attrset equality to weak head normal form, establishing the arena access
//! and diagnostic surface used by later slices for full string coercion,
//! first-class primitive operations, and derivation boundaries.

use std::rc::Rc;

use thiserror::Error;

use super::env::{EvalEnv, EvalEnvError, EvalFrame, EvalWithEnv, EvalWithScope};
use super::heap::{EvalHeap, EvalHeapError, EvalLambda, EvalThunk};
use super::thunk::{ForceClaim, ForceError};
use crate::attrs::{AttrEntry, AttrError, FlatAttrs};
use crate::compile::{
    FrameId, Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId,
    IrKind, IrNode, IrShapeId,
};
use crate::list::{NixList, NixListError};
use crate::string::{NixString, NixStringError};
use crate::syntax::{BinOpKind, Span, Symbol, SymbolTable, UnaryOpKind};
use crate::value::{Value, ValueTag};

const TO_STRING_ATTR: &[u8] = b"__toString";
const OUT_PATH_ATTR: &[u8] = b"outPath";
const NAME_ATTR: &[u8] = b"name";
const VALUE_ATTR: &[u8] = b"value";
const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;

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
    symbols: SymbolTable,
    heap: EvalHeap,
    env: Vec<Rc<EvalFrame>>,
    with_scopes: Vec<EvalWithScope>,
}

impl<'ir> TreeWalk<'ir> {
    /// Creates a tree-walk evaluator over `ir`.
    pub fn new(ir: &'ir Ir) -> Self {
        Self {
            ir,
            symbols: ir.symbols.clone(),
            heap: EvalHeap::new(),
            env: Vec::new(),
            with_scopes: Vec::new(),
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
    /// This initial public node entry point is intentionally limited to scalar
    /// literal, list literal, static attrset literal, string and URI literal,
    /// control-flow, boolean operator, string/list concatenation, attrset
    /// update, static
    /// attribute selection, lexical `let` environment, simple and formal-set
    /// lambda application, lazy `with` lookup, numeric arithmetic, numeric and
    /// string/list comparison, direct strict unary primops,
    /// scalar/string/function/list/attrset equality, and conservative thunk
    /// allocation nodes. Remaining environment-dependent nodes return
    /// [`TreeWalkErrorKind::UnsupportedNode`] until later slices add their
    /// explicit runtime context.
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
            IrKind::Interp => self.eval_interp(id, &node),
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::WithVar => self.eval_with_var(id, &node),
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
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedNode { id, kind },
                node.span,
            )),
        }?;
        self.force_value(id, node.span, value)
    }

    fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.ir.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    fn binding_range(
        &self,
        id: IrId,
        slice: IrBindingSlice,
        span: Span,
    ) -> Result<std::ops::Range<usize>, TreeWalkError> {
        let start = slice.start as usize;
        let end = start.checked_add(slice.len()).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidBindingSlice { id, slice }, span)
        })?;
        if self.ir.bindings.get(start..end).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidBindingSlice { id, slice },
                span,
            ));
        }
        Ok(start..end)
    }

    fn frame_info(
        &self,
        id: IrId,
        frame: FrameId,
        span: Span,
    ) -> Result<&crate::compile::FrameInfo, TreeWalkError> {
        self.ir.frames.get(frame.index()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidFrameId {
                    id,
                    frame: frame.as_u32(),
                },
                span,
            )
        })
    }

    fn capture_env(&self, id: IrId, span: Span) -> Result<EvalEnv, TreeWalkError> {
        EvalEnv::capture(&self.env)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    fn capture_with_env(&self, id: IrId, span: Span) -> Result<EvalWithEnv, TreeWalkError> {
        EvalWithEnv::capture(&self.with_scopes)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    fn clone_env_frames(
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

    fn clone_with_scopes(
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

    fn validate_attrset_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
        shape_keys: &[Symbol],
        binding_range: std::ops::Range<usize>,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let mut binding_keys = 0usize;
        for binding_index in binding_range {
            let binding = self.ir.bindings[binding_index];
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

    fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<&[IrAttrPathSegment], TreeWalkError> {
        self.ir
            .attr_paths
            .get(path.index())
            .map(|segments| segments.as_ref())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    fn attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.attr_path(id, path, span)
            .map(|segments| segments.len())
    }

    fn attr_path_segment(
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

    fn with_chain_scope_count(
        &self,
        id: IrId,
        chain: u32,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.ir
            .with_chains
            .get(chain as usize)
            .map(|chain| chain.scopes.len())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    fn with_chain_scope(
        &self,
        id: IrId,
        chain: u32,
        index: usize,
        span: Span,
    ) -> Result<IrId, TreeWalkError> {
        self.ir
            .with_chains
            .get(chain as usize)
            .and_then(|chain| chain.scopes.get(index).copied())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    fn with_scope_value(&self, id: IrId, scope: IrId, span: Span) -> Result<Value, TreeWalkError> {
        self.with_scopes
            .iter()
            .rev()
            .find(|active| active.scope() == scope)
            .map(EvalWithScope::value)
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::MissingWithScope { id, scope }, span)
            })
    }

    fn eval_global_fallback(
        &self,
        id: IrId,
        symbol: Symbol,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
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

    fn clone_attr_entries(
        id: IrId,
        span: Span,
        attrs: &FlatAttrs,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let entries = attrs.entries_by_symbol();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(entries.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: entries.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(entries);
        Ok(cloned)
    }

    fn clone_list_elements(
        id: IrId,
        span: Span,
        list: &NixList,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let elements = list.as_slice();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        cloned.extend_from_slice(elements);
        Ok(cloned)
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
            BinOpKind::Update => self.eval_attr_update(id, node, lhs, rhs),
            BinOpKind::PipeRight | BinOpKind::PipeLeft => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedBinaryOp { id, op },
                node.span,
            )),
        }
    }

    fn eval_string(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "string symbol payload"));
        };
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
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

    fn eval_interp(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        match node.data {
            IrData::Node(child) => {
                let span = self.node(child)?.span;
                let value = self.eval_node(child)?;
                self.coerce_to_string(child, value, span)
            }
            IrData::Children(children) => {
                let children = self.ir.arena.child_slice(children).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidChildSlice {
                            id,
                            slice: children,
                        },
                        node.span,
                    )
                })?;
                let Some((first, rest)) = children.split_first() else {
                    return self
                        .heap
                        .alloc_string(NixString::default())
                        .map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                        });
                };
                let first_span = self.node(*first)?.span;
                let mut current = {
                    let value = self.eval_node(*first)?;
                    self.coerce_to_string(*first, value, first_span)?
                };
                for child in rest {
                    let child_span = self.node(*child)?.span;
                    let next = {
                        let value = self.eval_node(*child)?;
                        self.coerce_to_string(*child, value, child_span)?
                    };
                    current = self.concat_strings(id, node, current, next)?;
                }
                Ok(current)
            }
            IrData::None => self
                .heap
                .alloc_string(NixString::default())
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                }),
            IrData::Symbol(symbol) => {
                let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
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
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                    })
            }
            _ => Err(self.invalid_payload(id, node, "interpolation payload")),
        }
    }

    fn coerce_to_string(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        match value.tag() {
            ValueTag::String => Ok(value),
            ValueTag::Attrs => self.coerce_attrs_to_string(id, value, span),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    fn coerce_attrs_to_string(
        &mut self,
        id: IrId,
        attrs_value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if let Some(hook) = self.attr_value_by_name(id, attrs_value, TO_STRING_ATTR, span)? {
            let hook = self.force_value(id, span, hook)?;
            let value = self.apply_lambda_value(id, span, id, hook, span, id, attrs_value)?;
            return self.coerce_to_string(id, value, span);
        }

        if let Some(out_path) = self.attr_value_by_name(id, attrs_value, OUT_PATH_ATTR, span)? {
            let value = self.force_value(id, span, out_path)?;
            return self.coerce_to_string(id, value, span);
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::Type {
                id,
                expected: "string",
                actual: ValueTag::Attrs,
            },
            span,
        ))
    }

    fn attr_value_by_name(
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

    fn eval_attr_name(
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
                self.eval_dynamic_attr_name(id, self.dynamic_attr_expression(dynamic)?, null_policy)
            }
        }
    }

    fn dynamic_attr_expression(&self, dynamic: IrId) -> Result<IrId, TreeWalkError> {
        let node = self.node(dynamic)?;
        if node.kind == IrKind::Interp {
            if let IrData::Node(child) = node.data {
                return Ok(child);
            }
        }
        Ok(dynamic)
    }

    fn eval_dynamic_attr_name(
        &mut self,
        id: IrId,
        expression: IrId,
        null_policy: DynamicAttrNullPolicy,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        let span = self.node(expression)?.span;
        let value = self.eval_node(expression)?;
        match value.tag() {
            ValueTag::Null if null_policy == DynamicAttrNullPolicy::SkipNull => Ok(None),
            _ => {
                let string = self.coerce_to_string(expression, value, span)?;
                self.intern_string_value(id, string, span).map(Some)
            }
        }
    }

    fn intern_string_value(
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
        self.symbols.intern(&bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })
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

    fn eval_local_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
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

    fn eval_upval_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
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

    fn eval_lazy_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        if node.kind == IrKind::ThunkAlloc {
            return self.eval_thunk_alloc(id, &node);
        }
        self.eval_node(id)
    }

    fn eval_nested_equality_operand(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        match node.kind {
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            _ => self.eval_node(id),
        }
    }

    fn eval_thunk_alloc(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Node(body) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        self.alloc_thunk_for_node(id, body, node.span)
    }

    fn alloc_thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        self.node(body)?;
        let env = self.capture_env(id, span)?;
        let with_env = self.capture_with_env(id, span)?;
        self.heap
            .alloc_thunk(EvalThunk::with_captures(body, env, with_env))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn force_value(&mut self, id: IrId, span: Span, value: Value) -> Result<Value, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(value);
        }
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let body = thunk.body();
        match thunk
            .cell()
            .begin_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            ForceClaim::AlreadyForced(value) => Ok(value),
            ForceClaim::Claimed(guard) => {
                let thunk_env = self.clone_env_frames(id, thunk.env(), span)?;
                let thunk_with_env = self.clone_with_scopes(id, thunk.with_scope_env(), span)?;
                let saved_env = std::mem::replace(&mut self.env, thunk_env);
                let saved_with_scopes = std::mem::replace(&mut self.with_scopes, thunk_with_env);
                let result = self.eval_node(body);
                self.env = saved_env;
                self.with_scopes = saved_with_scopes;
                let value = result?;
                guard.finish(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                })
            }
        }
    }

    fn eval_let(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
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
        let frame_values = EvalFrame::new(slot_count).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
        })?;
        self.env.push(Rc::clone(&frame_values));
        let result = (|| {
            for (slot, binding_index) in binding_range.enumerate() {
                let binding = self.ir.bindings[binding_index];
                if !matches!(binding.key, IrAttrPathSegment::Static(_)) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::UnsupportedLetBindingKey { id },
                        node.span,
                    ));
                }
                let value = self.eval_lazy_node(binding.value)?;
                frame_values.set(slot as u32, value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                })?;
            }
            self.eval_node(body)
        })();
        let _ = self.env.pop();
        result
    }

    fn eval_with(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair {
            first: scope,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "with pair"));
        };
        self.node(body)?;
        let value = self.alloc_thunk_for_node(id, scope, node.span)?;
        self.with_scopes.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::WithScopeAllocationFailed {
                    id,
                    scopes: self.with_scopes.len() + 1,
                },
                node.span,
            )
        })?;
        self.with_scopes.push(EvalWithScope::new(scope, value));
        let result = self.eval_node(body);
        let _ = self.with_scopes.pop();
        result
    }

    fn eval_with_var(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::WithVar { symbol, chain } = node.data else {
            return Err(self.invalid_payload(id, node, "with-var payload"));
        };
        if self.ir.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        }

        let scope_count = self.with_chain_scope_count(id, chain, node.span)?;
        for index in 0..scope_count {
            let scope = self.with_chain_scope(id, chain, index, node.span)?;
            let scope_span = self.node(scope)?.span;
            let scope_value = self.with_scope_value(id, scope, node.span)?;
            let attrs_value = self.force_value(scope, scope_span, scope_value)?;
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
            let selected = {
                let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(symbol)
            };
            if let Some(value) = selected {
                return Ok(value);
            }
        }

        self.eval_global_fallback(id, symbol, node.span)
    }

    fn eval_lambda(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
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
        let env = self.capture_env(id, node.span)?;
        let with_env = self.capture_with_env(id, node.span)?;
        self.heap
            .alloc_lambda(EvalLambda::with_captures(
                pattern, body, frame, env, with_env,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_apply(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair { first, second } = node.data else {
            return Err(self.invalid_payload(id, node, "application pair"));
        };
        let function_span = self.node(first)?.span;
        let function = self.eval_node(first)?;
        if function.tag() != ValueTag::Lambda {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: first,
                    expected: "lambda",
                    actual: function.tag(),
                },
                function_span,
            ));
        }
        let argument = self.eval_lazy_node(second)?;
        self.apply_lambda_value(
            id,
            node.span,
            first,
            function,
            function_span,
            second,
            argument,
        )
    }

    fn eval_primop(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::PrimOp { symbol, args } = node.data else {
            return Err(self.invalid_payload(id, node, "primop payload"));
        };
        let name = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let strict_binary = StrictBinaryPrimOp::from_bytes(name);
        let strict_unary = StrictUnaryPrimOp::from_bytes(name);
        let args = self.ir.arena.child_slice(args).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidChildSlice { id, slice: args },
                node.span,
            )
        })?;
        if let Some(primop) = strict_binary {
            if args.len() != 2 {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::InvalidPrimOpArity {
                        id,
                        symbol,
                        expected: 2,
                        actual: args.len(),
                    },
                    node.span,
                ));
            }

            let first = args[0];
            let second = args[1];
            return match primop {
                StrictBinaryPrimOp::ElemAt => self.eval_elem_at_primop(first, second),
                StrictBinaryPrimOp::GetAttr => {
                    self.eval_get_attr_primop(id, node.span, first, second)
                }
                StrictBinaryPrimOp::HasAttr => self.eval_has_attr_primop(first, second),
                StrictBinaryPrimOp::RemoveAttrs => {
                    self.eval_remove_attrs_primop(id, node.span, first, second)
                }
                StrictBinaryPrimOp::IntersectAttrs => {
                    self.eval_intersect_attrs_primop(id, node.span, first, second)
                }
                StrictBinaryPrimOp::CatAttrs => {
                    self.eval_cat_attrs_primop(id, node.span, first, second)
                }
                StrictBinaryPrimOp::Elem => self.eval_elem_primop(id, node, first, second),
                StrictBinaryPrimOp::LessThan => {
                    self.eval_comparison(id, node, ComparisonOp::Lt, first, second)
                }
                StrictBinaryPrimOp::Add => {
                    self.eval_numeric_binary(id, node, BinaryArithmeticOp::Add, first, second)
                }
                StrictBinaryPrimOp::Sub => {
                    self.eval_numeric_binary(id, node, BinaryArithmeticOp::Sub, first, second)
                }
                StrictBinaryPrimOp::Mul => {
                    self.eval_numeric_binary(id, node, BinaryArithmeticOp::Mul, first, second)
                }
                StrictBinaryPrimOp::Div => {
                    self.eval_numeric_binary(id, node, BinaryArithmeticOp::Div, first, second)
                }
                StrictBinaryPrimOp::BitAnd => {
                    self.eval_bitwise_primop(BitwiseOp::And, first, second)
                }
                StrictBinaryPrimOp::BitOr => self.eval_bitwise_primop(BitwiseOp::Or, first, second),
                StrictBinaryPrimOp::BitXor => {
                    self.eval_bitwise_primop(BitwiseOp::Xor, first, second)
                }
            };
        }
        if args.len() != 1 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidPrimOpArity {
                    id,
                    symbol,
                    expected: 1,
                    actual: args.len(),
                },
                node.span,
            ));
        }

        let argument = args[0];
        let value = self.eval_node(argument)?;
        let Some(primop) = strict_unary else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                node.span,
            ));
        };
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
                        self.node(argument)?.span,
                    ));
                };
                self.alloc_static_string(id, node.span, name.as_bytes())
            }
            StrictUnaryPrimOp::Length => {
                let argument_span = self.node(argument)?.span;
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
                Ok(Value::int(len))
            }
            StrictUnaryPrimOp::AttrNames => {
                let argument_span = self.node(argument)?.span;
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
                let names = {
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
                            node.span,
                        )
                    })?;
                    for entry in attrs.iter_lexicographic() {
                        names.push(entry.key);
                    }
                    names
                };
                let mut elements = Vec::new();
                elements.try_reserve_exact(names.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: names.len(),
                        },
                        node.span,
                    )
                })?;
                for symbol in names {
                    elements.push(self.alloc_symbol_string(id, node.span, symbol)?);
                }
                self.heap
                    .alloc_list(NixList::new(elements))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                    })
            }
            StrictUnaryPrimOp::AttrValues => {
                let argument_span = self.node(argument)?.span;
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
                let values = {
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
                            node.span,
                        )
                    })?;
                    for entry in attrs.iter_lexicographic() {
                        values.push(entry.value);
                    }
                    values
                };
                self.heap
                    .alloc_list(NixList::new(values))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                    })
            }
            StrictUnaryPrimOp::Tail => {
                let argument_span = self.node(argument)?.span;
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
                            node.span,
                        )
                    })?;
                    values.extend_from_slice(tail);
                    values
                };
                self.heap
                    .alloc_list(NixList::new(values))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                    })
            }
            StrictUnaryPrimOp::Head => {
                let argument_span = self.node(argument)?.span;
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
                node.span,
                argument,
                value,
                f64::ceil,
                ArithmeticOp::Ceil,
            ),
            StrictUnaryPrimOp::Floor => self.eval_float_to_int_primop(
                id,
                node.span,
                argument,
                value,
                f64::floor,
                ArithmeticOp::Floor,
            ),
            StrictUnaryPrimOp::HasContext => {
                let argument_span = self.node(argument)?.span;
                self.eval_has_context_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::FunctionArgs => {
                let argument_span = self.node(argument)?.span;
                self.eval_function_args_primop(id, node.span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ListToAttrs => {
                let argument_span = self.node(argument)?.span;
                self.eval_list_to_attrs_primop(id, node.span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ConcatLists => {
                let argument_span = self.node(argument)?.span;
                self.eval_concat_lists_primop(id, node.span, argument, argument_span, value)
            }
        }
    }

    fn eval_float_to_int_primop(
        &self,
        id: IrId,
        span: Span,
        argument: IrId,
        value: Value,
        op: fn(f64) -> f64,
        arithmetic_op: ArithmeticOp,
    ) -> Result<Value, TreeWalkError> {
        let argument_span = self.node(argument)?.span;
        let value = match self.expect_number(argument, value, argument_span)? {
            Number::Int(value) => value,
            Number::Float(value) => {
                let rounded = op(value);
                if rounded.is_nan() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::ArithmeticOverflow {
                            id,
                            op: arithmetic_op,
                        },
                        span,
                    ));
                }
                if rounded <= i64::MIN as f64 {
                    i64::MIN
                } else if rounded >= I64_MAX_EXCLUSIVE_AS_F64 {
                    i64::MAX
                } else {
                    rounded as i64
                }
            }
        };
        Ok(Value::int(value))
    }

    fn eval_has_context_primop(
        &self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "string",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(Value::bool(string.has_context()))
    }

    fn eval_list_to_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
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
        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: argument,
                        len: list.len(),
                    },
                    argument_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        let name_attr = self.intern_builtin_attr_symbol(id, NAME_ATTR, span)?;
        let value_attr = self.intern_builtin_attr_symbol(id, VALUE_ATTR, span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: elements.len(),
                    },
                },
                span,
            )
        })?;

        for element in elements {
            let element = self.force_value(argument, argument_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    argument_span,
                ));
            }
            let name_value = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                attrs.get(name_attr).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute {
                            id: argument,
                            symbol: name_attr,
                        },
                        argument_span,
                    )
                })?
            };
            let name_value = self.force_value(argument, argument_span, name_value)?;
            if name_value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "string",
                        actual: name_value.tag(),
                    },
                    argument_span,
                ));
            }
            let key = self.intern_string_value(argument, name_value, argument_span)?;
            if entries.iter().any(|entry: &AttrEntry| entry.key == key) {
                continue;
            }

            let attr_value = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                attrs.get(value_attr).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute {
                            id: argument,
                            symbol: value_attr,
                        },
                        argument_span,
                    )
                })?
            };
            entries.push(AttrEntry::new(key, attr_value));
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_concat_lists_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
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
        let lists = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            Self::clone_list_elements(argument, argument_span, list)?
        };

        let mut elements = Vec::new();
        for list_value in lists {
            let list_value = self.force_value(argument, argument_span, list_value)?;
            if list_value.tag() != ValueTag::List {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "list",
                        actual: list_value.tag(),
                    },
                    argument_span,
                ));
            }
            let inner = {
                let list = self.heap.get_list(list_value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                Self::clone_list_elements(argument, argument_span, list)?
            };
            let len = elements.len().checked_add(inner.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::LengthOverflow {
                            left: elements.len(),
                            right: inner.len(),
                        },
                    },
                    span,
                )
            })?;
            elements.try_reserve_exact(inner.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::AllocationFailed { len },
                    },
                    span,
                )
            })?;
            elements.extend(inner);
        }
        self.heap
            .alloc_list(NixList::new(elements))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn intern_builtin_attr_symbol(
        &mut self,
        id: IrId,
        name: &[u8],
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        self.symbols.intern(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                span,
            )
        })
    }

    fn eval_elem_at_primop(
        &mut self,
        list_id: IrId,
        index_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let index_span = self.node(index_id)?.span;
        let index_value = self.eval_node(index_id)?;
        if index_value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: index_id,
                    expected: "int",
                    actual: index_value.tag(),
                },
                index_span,
            ));
        }
        let index = index_value.payload_bits() as i64;
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let list = self.heap.get_list(list_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: list_id,
                    source,
                },
                list_span,
            )
        })?;
        let Some(value) = usize::try_from(index)
            .ok()
            .and_then(|index| list.get(index))
        else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index_id,
                    index,
                    len: list.len(),
                },
                index_span,
            ));
        };
        Ok(value)
    }

    fn eval_elem_primop(
        &mut self,
        id: IrId,
        node: &IrNode,
        candidate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };
        if elements.is_empty() {
            return Ok(Value::bool(false));
        }

        let candidate_span = self.node(candidate_id)?.span;
        let candidate = self.eval_nested_equality_operand(candidate_id)?;
        for element in elements {
            if self.values_equal_nested_lazy(
                id,
                node,
                candidate_id,
                candidate_span,
                candidate,
                list_id,
                list_span,
                element,
            )? {
                return Ok(Value::bool(true));
            }
        }
        Ok(Value::bool(false))
    }

    fn eval_get_attr_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_node(attrs_id)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }
        let selected = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.get(key)
        };
        selected.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                span,
            )
        })
    }

    fn eval_has_attr_primop(
        &mut self,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_node(attrs_id)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }
        let has_attr = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.contains_key(key)
        };
        Ok(Value::bool(has_attr))
    }

    fn eval_attr_name_primop_argument(&mut self, id: IrId) -> Result<Symbol, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
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
        self.intern_string_value(id, value, span)
    }

    fn eval_remove_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        names_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_node(attrs_id)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }

        let names_span = self.node(names_id)?.span;
        let names_value = self.eval_node(names_id)?;
        if names_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: names_id,
                    expected: "list",
                    actual: names_value.tag(),
                },
                names_span,
            ));
        }
        let name_values = {
            let names = self.heap.get_list(names_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: names_id,
                        source,
                    },
                    names_span,
                )
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(names.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: names_id,
                        len: names.len(),
                    },
                    names_span,
                )
            })?;
            values.extend_from_slice(names.as_slice());
            values
        };
        let mut remove = Vec::new();
        remove.try_reserve_exact(name_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: names_id,
                    len: name_values.len(),
                },
                names_span,
            )
        })?;
        for value in name_values {
            let value = self.force_value(names_id, names_span, value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: names_id,
                        expected: "string",
                        actual: value.tag(),
                    },
                    names_span,
                ));
            }
            let key = self.intern_string_value(names_id, value, names_span)?;
            if !remove.contains(&key) {
                remove.push(key);
            }
        }

        let entries = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: attrs.len(),
                    },
                    span,
                )
            })?;
            for entry in attrs.entries_by_symbol() {
                if !remove.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_intersect_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        left_id: IrId,
        right_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left_span = self.node(left_id)?.span;
        let left_value = self.eval_node(left_id)?;
        if left_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: left_id,
                    expected: "attrs",
                    actual: left_value.tag(),
                },
                left_span,
            ));
        }

        let right_span = self.node(right_id)?.span;
        let right_value = self.eval_node(right_id)?;
        if right_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: right_id,
                    expected: "attrs",
                    actual: right_value.tag(),
                },
                right_span,
            ));
        }

        let left_keys = {
            let left = self.heap.get_attrs(left_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: left_id,
                        source,
                    },
                    left_span,
                )
            })?;
            let mut keys = Vec::new();
            keys.try_reserve_exact(left.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: left_id,
                        len: left.len(),
                    },
                    left_span,
                )
            })?;
            keys.extend(left.entries_by_symbol().iter().map(|entry| entry.key));
            keys
        };
        let entries = {
            let right = self.heap.get_attrs(right_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: right_id,
                        source,
                    },
                    right_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(right.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: right.len(),
                    },
                    span,
                )
            })?;
            for entry in right.entries_by_symbol() {
                if left_keys.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_cat_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };
        let mut values = Vec::new();
        values.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let element = self.force_value(list_id, list_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: list_id,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    list_span,
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list_id,
                            source,
                        },
                        list_span,
                    )
                })?;
                attrs.get(key)
            };
            if let Some(value) = selected {
                values.push(value);
            }
        }
        self.heap
            .alloc_list(NixList::new(values))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_function_args_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let entries = match value.tag() {
            ValueTag::Lambda => {
                let lambda = self.heap.clone_lambda(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                self.function_args_entries(id, span, lambda.pattern())?
            }
            ValueTag::Primop => Vec::new(),
            actual => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "function",
                        actual,
                    },
                    argument_span,
                ));
            }
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn function_args_entries(
        &self,
        id: IrId,
        span: Span,
        pattern: IrId,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let pattern_node = *self.node(pattern)?;
        match pattern_node.kind {
            IrKind::Formal => Ok(Vec::new()),
            IrKind::FormalSet => {
                let IrData::FormalSet { formals, .. } = pattern_node.data else {
                    return Err(self.invalid_payload(pattern, &pattern_node, "formal-set payload"));
                };
                let formal_slice = self.ir.arena.child_slice(formals).ok_or_else(|| {
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
                            id,
                            len: formal_slice.len(),
                        },
                        span,
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
                    entries.push(AttrEntry::new(name, Value::bool(default.is_some())));
                }
                Ok(entries)
            }
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedLambdaPattern { id, pattern, kind },
                pattern_node.span,
            )),
        }
    }

    fn alloc_static_string(
        &mut self,
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.heap
            .alloc_string(NixString::from_bytes(owned))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn alloc_symbol_string(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
    ) -> Result<Value, TreeWalkError> {
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, span)
        })?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.heap
            .alloc_string(NixString::from_bytes(owned))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn apply_lambda_value(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        if function.tag() != ValueTag::Lambda {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function_id,
                    expected: "lambda",
                    actual: function.tag(),
                },
                function_span,
            ));
        }
        let lambda = self.heap.clone_lambda(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        let slot_count = self.frame_info(id, lambda.frame(), span)?.slot_count as usize;
        let call_frame = EvalFrame::new(slot_count)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))?;
        let mut call_env = self.clone_env_frames(id, lambda.env(), span)?;
        let call_with_env = self.clone_with_scopes(id, lambda.with_scope_env(), span)?;
        call_env.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: call_env.len() + 1,
                    },
                },
                span,
            )
        })?;
        call_env.push(call_frame);
        let saved_env = std::mem::replace(&mut self.env, call_env);
        let saved_with_scopes = std::mem::replace(&mut self.with_scopes, call_with_env);
        let result = (|| {
            let call_frame = self.env.last().cloned().ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::MissingEnvironment { id }, span)
            })?;
            self.bind_lambda_argument(
                id,
                lambda.pattern(),
                slot_count,
                &call_frame,
                argument_id,
                argument,
                span,
            )?;
            self.eval_node(lambda.body())
        })();
        self.env = saved_env;
        self.with_scopes = saved_with_scopes;
        result
    }

    fn bind_lambda_argument(
        &mut self,
        id: IrId,
        pattern: IrId,
        slot_count: usize,
        frame: &EvalFrame,
        argument_id: IrId,
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
    fn bind_formal_set_argument(
        &mut self,
        id: IrId,
        pattern: IrId,
        pattern_node: &IrNode,
        slot_count: usize,
        frame: &EvalFrame,
        argument_id: IrId,
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
        let formal_slice = self.ir.arena.child_slice(formals).ok_or_else(|| {
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
            if self.ir.symbols.resolve(name).is_none() {
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
        if let Some(alias) = alias {
            if self.ir.symbols.resolve(alias).is_none() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: pattern,
                        symbol: alias,
                    },
                    pattern_node.span,
                ));
            }
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

        let argument_span = self.node(argument_id)?.span;
        let attrs_value = self.force_value(argument_id, argument_span, argument)?;
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

    fn eval_attrset(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::AttrSet {
            shape,
            bindings,
            recursive,
            has_dynamic: _,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "attrset payload"));
        };
        let binding_range = self.binding_range(id, bindings, node.span)?;
        {
            let shape_keys = self
                .ir
                .shapes
                .get(shape.index())
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidShapeId { id, shape }, node.span)
                })?
                .keys
                .as_ref();
            self.validate_attrset_shape(id, shape, shape_keys, binding_range.clone(), node.span)?;
        }
        let static_bindings = binding_range
            .clone()
            .filter(|binding_index| {
                matches!(
                    self.ir.bindings[*binding_index].key,
                    IrAttrPathSegment::Static(_)
                )
            })
            .count();
        let dynamic_key_env = if recursive {
            Some(self.env.clone())
        } else {
            None
        };
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
            Some(EvalFrame::new(slot_count).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
            })?)
        } else {
            None
        };
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
            self.env.push(Rc::clone(frame_values));
        }
        let result = (|| {
            if let Some(frame_values) = &frame_values {
                let mut slot = 0u32;
                for binding_index in binding_range.clone() {
                    let binding = self.ir.bindings[binding_index];
                    if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                        let value = self.eval_lazy_node(binding.value)?;
                        frame_values.set(slot, value).map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                        })?;
                        slot += 1;
                    }
                }
            }

            let mut slot = 0u32;
            for binding_index in binding_range {
                let binding = self.ir.bindings[binding_index];
                let key = if matches!(binding.key, IrAttrPathSegment::Dynamic(_)) {
                    if let Some(dynamic_key_env) = &dynamic_key_env {
                        let saved_env = std::mem::replace(&mut self.env, dynamic_key_env.clone());
                        let result = self.eval_attr_name(
                            id,
                            binding.key,
                            DynamicAttrNullPolicy::SkipNull,
                            node.span,
                        );
                        self.env = saved_env;
                        result?
                    } else {
                        self.eval_attr_name(
                            id,
                            binding.key,
                            DynamicAttrNullPolicy::SkipNull,
                            node.span,
                        )?
                    }
                } else {
                    self.eval_attr_name(
                        id,
                        binding.key,
                        DynamicAttrNullPolicy::SkipNull,
                        node.span,
                    )?
                };
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
                        self.eval_lazy_node(binding.value)?
                    }
                } else {
                    self.eval_lazy_node(binding.value)?
                };
                entries.push(AttrEntry::new(key, value));
            }
            Ok(entries)
        })();
        if recursive {
            let _ = self.env.pop();
        }
        let entries = result?;

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        self.heap
            .alloc_attrs(shape.as_u32(), attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_select(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Select {
            receiver,
            path: path_id,
            default,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "select payload"));
        };
        let segments = self.attr_path_len(id, path_id, node.span)?;
        let mut current = self.eval_node(receiver)?;
        if segments == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedAttrPath {
                    id,
                    path: path_id,
                    segments,
                    has_dynamic: false,
                },
                node.span,
            ));
        }

        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, node.span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, node.span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        node.span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "attrs",
                            actual: current.tag(),
                        },
                        node.span,
                    )),
                };
            }
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(key)
            };
            let Some(value) = selected else {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                        node.span,
                    )),
                };
            };
            if index + 1 == segments {
                return Ok(value);
            }
            current = self.force_value(id, node.span, value)?;
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedAttrPath {
                id,
                path: path_id,
                segments,
                has_dynamic: false,
            },
            node.span,
        ))
    }

    fn eval_has_attr(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::HasAttr {
            receiver,
            path: path_id,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "has-attr payload"));
        };
        let segments = self.attr_path_len(id, path_id, node.span)?;
        let mut current = self.eval_node(receiver)?;
        if segments == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedAttrPath {
                    id,
                    path: path_id,
                    segments,
                    has_dynamic: false,
                },
                node.span,
            ));
        }

        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, node.span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, node.span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        node.span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return Ok(Value::bool(false));
            }
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(key)
            };
            let Some(value) = selected else {
                return Ok(Value::bool(false));
            };
            if index + 1 == segments {
                return Ok(Value::bool(true));
            }
            current = self.force_value(id, node.span, value)?;
        }

        Ok(Value::bool(false))
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
        let equal = self.values_equal(id, node, left, right, EqualityContext::Direct)?;
        Ok(Value::bool(if invert { !equal } else { equal }))
    }

    fn values_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        _context: EqualityContext,
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
            (ValueTag::List, ValueTag::List) => self.lists_equal(id, node, left, right),
            (ValueTag::Attrs, ValueTag::Attrs) => self.attrsets_equal(id, node, left, right),
            (ValueTag::Lambda | ValueTag::Primop, ValueTag::Lambda | ValueTag::Primop) => Ok(false),
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

    fn values_equal_nested_lazy(
        &mut self,
        id: IrId,
        node: &IrNode,
        left_id: IrId,
        left_span: Span,
        left: Value,
        right_id: IrId,
        right_span: Span,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_identity = self.nested_identity_value(id, node.span, left)?;
        let right_identity = self.nested_identity_value(id, node.span, right)?;
        let shared_heap_identity =
            left_identity.raw_eq(right_identity) && left_identity.tag().is_heap();
        if shared_heap_identity && left_identity.tag() != ValueTag::Thunk {
            return Ok(true);
        }

        let left = self.force_value(left_id, left_span, left_identity)?;
        let right = self.force_value(right_id, right_span, right_identity)?;
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
            && f64::from_bits(left.payload_bits()).is_nan()
            && f64::from_bits(right.payload_bits()).is_nan()
        {
            return Ok(true);
        }
        self.values_equal(id, node, left, right, EqualityContext::Nested)
    }

    fn nested_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::Thunk {
            return Ok(value);
        }
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let body = thunk.body();
        let body_node = *self.node(body)?;
        if !matches!(
            body_node.kind,
            IrKind::LocalVar | IrKind::UpvalVar | IrKind::ThunkAlloc
        ) {
            return Ok(value);
        }

        let thunk_env = self.clone_env_frames(id, thunk.env(), span)?;
        let thunk_with_env = self.clone_with_scopes(id, thunk.with_scope_env(), span)?;
        let saved_env = std::mem::replace(&mut self.env, thunk_env);
        let saved_with_scopes = std::mem::replace(&mut self.with_scopes, thunk_with_env);
        let result = self.eval_nested_equality_operand(body);
        self.env = saved_env;
        self.with_scopes = saved_with_scopes;
        result
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

    fn lists_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        if left_elements.len() != right_elements.len() {
            return Ok(false);
        }

        for (left, right) in left_elements.into_iter().zip(right_elements) {
            if !self
                .values_equal_nested_lazy(id, node, id, node.span, left, id, node.span, right)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn attrsets_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
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
            if !self.values_equal_nested_lazy(
                id,
                node,
                id,
                node.span,
                left.value,
                id,
                node.span,
                right.value,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
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
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let left = self.expect_number(lhs, left, lhs_span)?;
        let right = self.expect_number(rhs, right, rhs_span)?;
        self.eval_numeric_values(id, node, op, left, right)
    }

    fn eval_bitwise_primop(
        &mut self,
        op: BitwiseOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left = self.eval_int_node(lhs)?;
        let right = self.eval_int_node(rhs)?;

        Ok(Value::int(op.apply(left, right)))
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

    fn eval_attr_update(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
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
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        self.eval_comparison_values(id, node, op, lhs, lhs_span, left, rhs, rhs_span, right)
    }

    fn eval_comparison_values(
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
    ) -> Result<Value, TreeWalkError> {
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let left = self.expect_number(lhs, left, lhs_span)?;
                let right = self.expect_number(rhs, right, rhs_span)?;
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
                    ));
                }
                self.compare_strings(id, node, op, left, right)
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
                    ));
                }
                self.compare_lists(id, node, op, left, right)
                    .map(Value::bool)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number, string, or list",
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

    fn compare_lists(
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

    fn compare_lists_with_guard(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        if !equality_guard.enter(left, right) {
            return Ok(op.compare_equal());
        }

        let result =
            self.compare_list_entries_with_guard(id, node, op, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    fn compare_list_entries_with_guard(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };

        for (left, right) in left_elements
            .iter()
            .copied()
            .zip(right_elements.iter().copied())
        {
            let left = self.force_value(id, node.span, left)?;
            let right = self.force_value(id, node.span, right)?;
            if self.values_equal_for_ordering(id, node, left, right, equality_guard)? {
                continue;
            }
            return self.compare_values_for_ordering(id, node, op, left, right, equality_guard);
        }

        Ok(op.compare_lengths(left_elements.len(), right_elements.len()))
    }

    fn compare_values_for_ordering(
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
                    expected: "number, string, or list",
                    actual,
                },
                node.span,
            )),
        }
    }

    fn values_equal_for_ordering(
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

    fn lists_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        if !equality_guard.enter(left, right) {
            return Ok(true);
        }

        let result = self.list_entries_equal_for_ordering(id, node, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    fn list_entries_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        if left_elements.len() != right_elements.len() {
            return Ok(false);
        }

        for (left, right) in left_elements.into_iter().zip(right_elements) {
            let left = self.force_value(id, node.span, left)?;
            let right = self.force_value(id, node.span, right)?;
            if !self.values_equal_for_ordering(id, node, left, right, equality_guard)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn attrsets_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        if !equality_guard.enter(left, right) {
            return Ok(true);
        }

        let result = self.attrset_entries_equal_for_ordering(id, node, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    fn attrset_entries_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
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
            let left = self.force_value(id, node.span, left.value)?;
            let right = self.force_value(id, node.span, right.value)?;
            if !self.values_equal_for_ordering(id, node, left, right, equality_guard)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn eval_integer_binary(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: i64,
        right: i64,
    ) -> Result<Value, TreeWalkError> {
        match op {
            BinaryArithmeticOp::Add => Ok(Value::int(left.wrapping_add(right))),
            BinaryArithmeticOp::Sub => Ok(Value::int(left.wrapping_sub(right))),
            BinaryArithmeticOp::Mul => Ok(Value::int(left.wrapping_mul(right))),
            BinaryArithmeticOp::Div => {
                if right == 0 {
                    return Err(self.division_by_zero(id, node));
                }
                left.checked_div(right).map(Value::int).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ArithmeticOverflow {
                            id,
                            op: ArithmeticOp::Div,
                        },
                        node.span,
                    )
                })
            }
        }
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

    fn eval_int_node(&mut self, id: IrId) -> Result<i64, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_int(id, value, span)
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

    fn expect_int(&self, id: IrId, value: Value, span: Span) -> Result<i64, TreeWalkError> {
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
        Ok(value.payload_bits() as i64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Number {
    Int(i64),
    Float(f64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DynamicAttrNullPolicy {
    SkipNull,
    RejectNull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EqualityContext {
    Direct,
    Nested,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrictUnaryPrimOp {
    IsAttrs,
    IsList,
    IsFunction,
    IsString,
    IsInt,
    IsFloat,
    IsBool,
    IsNull,
    IsPath,
    TypeOf,
    Length,
    AttrNames,
    AttrValues,
    Tail,
    FunctionArgs,
    Head,
    Ceil,
    Floor,
    HasContext,
    ListToAttrs,
    ConcatLists,
}

impl StrictUnaryPrimOp {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"isAttrs" => Some(Self::IsAttrs),
            b"isList" => Some(Self::IsList),
            b"isFunction" => Some(Self::IsFunction),
            b"isString" => Some(Self::IsString),
            b"isInt" => Some(Self::IsInt),
            b"isFloat" => Some(Self::IsFloat),
            b"isBool" => Some(Self::IsBool),
            b"isNull" => Some(Self::IsNull),
            b"isPath" => Some(Self::IsPath),
            b"typeOf" => Some(Self::TypeOf),
            b"length" => Some(Self::Length),
            b"attrNames" => Some(Self::AttrNames),
            b"attrValues" => Some(Self::AttrValues),
            b"tail" => Some(Self::Tail),
            b"functionArgs" => Some(Self::FunctionArgs),
            b"head" => Some(Self::Head),
            b"ceil" => Some(Self::Ceil),
            b"floor" => Some(Self::Floor),
            b"hasContext" => Some(Self::HasContext),
            b"listToAttrs" => Some(Self::ListToAttrs),
            b"concatLists" => Some(Self::ConcatLists),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrictBinaryPrimOp {
    Add,
    Sub,
    Mul,
    Div,
    BitAnd,
    BitOr,
    BitXor,
    ElemAt,
    GetAttr,
    HasAttr,
    RemoveAttrs,
    IntersectAttrs,
    CatAttrs,
    Elem,
    LessThan,
}

impl StrictBinaryPrimOp {
    fn from_bytes(name: &[u8]) -> Option<Self> {
        match name {
            b"add" => Some(Self::Add),
            b"sub" => Some(Self::Sub),
            b"mul" => Some(Self::Mul),
            b"div" => Some(Self::Div),
            b"bitAnd" => Some(Self::BitAnd),
            b"bitOr" => Some(Self::BitOr),
            b"bitXor" => Some(Self::BitXor),
            b"elemAt" => Some(Self::ElemAt),
            b"getAttr" => Some(Self::GetAttr),
            b"hasAttr" => Some(Self::HasAttr),
            b"removeAttrs" => Some(Self::RemoveAttrs),
            b"intersectAttrs" => Some(Self::IntersectAttrs),
            b"catAttrs" => Some(Self::CatAttrs),
            b"elem" => Some(Self::Elem),
            b"lessThan" => Some(Self::LessThan),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct EqualityPairGuard {
    active: Vec<(Value, Value)>,
}

impl EqualityPairGuard {
    fn enter(&mut self, left: Value, right: Value) -> bool {
        if self.active.iter().any(|(active_left, active_right)| {
            (active_left.raw_eq(left) && active_right.raw_eq(right))
                || (active_left.raw_eq(right) && active_right.raw_eq(left))
        }) {
            return false;
        }
        self.active.push((left, right));
        true
    }

    fn exit(&mut self, left: Value, right: Value) {
        let active = self.active.pop();
        debug_assert!(active.is_some_and(|(active_left, active_right)| {
            active_left.raw_eq(left) && active_right.raw_eq(right)
        }));
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BitwiseOp {
    And,
    Or,
    Xor,
}

impl BitwiseOp {
    const fn apply(self, left: i64, right: i64) -> i64 {
        match self {
            Self::And => left & right,
            Self::Or => left | right,
            Self::Xor => left ^ right,
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

    const fn compare_equal(self) -> bool {
        match self {
            Self::Lt | Self::Gt => false,
            Self::Le | Self::Ge => true,
        }
    }

    const fn compare_lengths(self, left: usize, right: usize) -> bool {
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
    /// Float-to-integer ceiling.
    Ceil,
    /// Float-to-integer floor.
    Floor,
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
    /// An attribute-path side-table id did not resolve through the IR.
    #[error("invalid attribute path {path:?} at node {id:?}")]
    InvalidAttrPath {
        /// The node id carrying the invalid attribute-path id.
        id: IrId,
        /// The invalid attribute-path id payload.
        path: IrAttrPathId,
    },
    /// A binding-table slice payload did not resolve through the IR.
    #[error("invalid binding slice {slice:?} at node {id:?}")]
    InvalidBindingSlice {
        /// The node id carrying the invalid binding slice.
        id: IrId,
        /// The invalid binding slice payload.
        slice: IrBindingSlice,
    },
    /// An attrset shape id payload did not resolve through the IR.
    #[error("invalid attrset shape {shape:?} at node {id:?}")]
    InvalidShapeId {
        /// The node id carrying the invalid shape id.
        id: IrId,
        /// The invalid shape id payload.
        shape: IrShapeId,
    },
    /// A node that needs a resolver frame referenced none.
    #[error("missing frame metadata at node {id:?}")]
    MissingFrameMetadata {
        /// The malformed node id.
        id: IrId,
    },
    /// A resolver frame id did not resolve through the IR.
    #[error("invalid frame id {frame} at node {id:?}")]
    InvalidFrameId {
        /// The node id carrying the invalid frame id.
        id: IrId,
        /// The invalid frame id payload.
        frame: u32,
    },
    /// A with-chain id did not resolve through the lowered IR.
    #[error("invalid with-chain id {chain} at node {id:?}")]
    InvalidWithChain {
        /// The node id carrying the invalid with-chain id.
        id: IrId,
        /// The invalid with-chain id payload.
        chain: u32,
    },
    /// A with-chain scope did not have a matching active runtime scope.
    #[error("missing active with scope {scope:?} at node {id:?}")]
    MissingWithScope {
        /// The with-variable node id.
        id: IrId,
        /// The lowered scope node id from the with-chain.
        scope: IrId,
    },
    /// A let frame's slot count did not match its binding table.
    #[error("let frame at node {id:?} has {frame_slots} slots for {bindings} bindings")]
    LetFrameSlotMismatch {
        /// The malformed let node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of lowered bindings.
        bindings: usize,
    },
    /// A recursive attrset frame's slot count did not match its binding table.
    #[error(
        "recursive attrset frame at node {id:?} has {frame_slots} slots for {bindings} bindings"
    )]
    AttrSetFrameSlotMismatch {
        /// The malformed attrset node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of lowered bindings.
        bindings: usize,
    },
    /// A lambda frame's slot count did not match the supported pattern.
    #[error(
        "lambda frame at node {id:?} has {frame_slots} slots for {pattern_slots} pattern slots"
    )]
    LambdaFrameSlotMismatch {
        /// The malformed lambda or application node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of slots expected by the supported pattern.
        pattern_slots: usize,
    },
    /// A lambda used a parameter pattern not implemented by this evaluator slice.
    #[error("unsupported lambda pattern {pattern:?} ({kind:?}) at node {id:?}")]
    UnsupportedLambdaPattern {
        /// The application node id.
        id: IrId,
        /// The unsupported pattern node id.
        pattern: IrId,
        /// The unsupported pattern node kind.
        kind: IrKind,
    },
    /// A local variable was evaluated without an active environment frame.
    #[error("missing lexical environment at node {id:?}")]
    MissingEnvironment {
        /// The variable node id.
        id: IrId,
    },
    /// An upvalue depth did not resolve through the active environment stack.
    #[error("upvalue depth {depth} at node {id:?} exceeds {frames} active frames")]
    InvalidUpvalueDepth {
        /// The upvalue node id.
        id: IrId,
        /// The requested parent depth.
        depth: usize,
        /// The number of active frames.
        frames: usize,
    },
    /// A let binding carried an unsupported dynamic key.
    #[error("unsupported let binding key at node {id:?}")]
    UnsupportedLetBindingKey {
        /// The malformed let node id.
        id: IrId,
    },
    /// An attrset shape has a different number of keys than its binding slice.
    #[error(
        "attrset shape {shape:?} at node {id:?} has {shape_keys} keys for {binding_keys} binding keys"
    )]
    AttrSetShapeLengthMismatch {
        /// The attrset node id carrying the mismatched metadata.
        id: IrId,
        /// The shape id carrying the mismatched key table.
        shape: IrShapeId,
        /// The number of keys recorded in the shape table.
        shape_keys: usize,
        /// The number of static keys found in the binding slice.
        binding_keys: usize,
    },
    /// An attrset shape key does not match the corresponding binding key.
    #[error(
        "attrset shape {shape:?} at node {id:?} key {index} is {expected:?}, but binding key is {actual:?}"
    )]
    AttrSetShapeKeyMismatch {
        /// The attrset node id carrying the mismatched metadata.
        id: IrId,
        /// The shape id carrying the mismatched key table.
        shape: IrShapeId,
        /// The mismatched key index.
        index: usize,
        /// The symbol recorded by the shape table.
        expected: Symbol,
        /// The symbol found in the binding slice.
        actual: Symbol,
    },
    /// A symbol payload did not resolve through the IR symbol table.
    #[error("invalid symbol {symbol:?} at node {id:?}")]
    InvalidSymbol {
        /// The node id associated with the missing symbol.
        id: IrId,
        /// The unresolved symbol payload.
        symbol: Symbol,
    },
    /// A runtime-computed attribute name could not be interned.
    #[error("runtime attribute-name interning failed at node {id:?}: {source}")]
    SymbolIntern {
        /// The node id associated with the runtime attribute name.
        id: IrId,
        /// The underlying symbol-table failure.
        source: crate::syntax::AstErrorKind,
    },
    /// A byte buffer for a string literal could not be reserved.
    #[error("failed to reserve {len} string bytes at node {id:?}")]
    ByteAllocationFailed {
        /// The string node id.
        id: IrId,
        /// The requested byte length.
        len: usize,
    },
    /// A list spine buffer could not be reserved.
    #[error("failed to reserve {len} list elements at node {id:?}")]
    ListAllocationFailed {
        /// The list node id.
        id: IrId,
        /// The requested list length.
        len: usize,
    },
    /// A list length could not fit in the Nix integer type.
    #[error("list length {len} at node {id:?} does not fit in i64")]
    ListLengthOverflow {
        /// The list-valued node whose length overflowed.
        id: IrId,
        /// The overflowing list length.
        len: usize,
    },
    /// A list primop received an empty list where it requires an element.
    #[error("{op} received an empty list at node {id:?}")]
    EmptyListPrimOp {
        /// The list-valued node that was empty.
        id: IrId,
        /// The primop that rejected the empty list.
        op: &'static str,
    },
    /// A list primop index was outside the list spine.
    #[error("list index {index} out of bounds for length {len} at node {id:?}")]
    ListIndexOutOfBounds {
        /// The index-valued node that was outside the list.
        id: IrId,
        /// The requested signed index.
        index: i64,
        /// The list spine length.
        len: usize,
    },
    /// The active with-scope stack could not reserve another entry.
    #[error("failed to reserve {scopes} active with scopes at node {id:?}")]
    WithScopeAllocationFailed {
        /// The with-expression node id.
        id: IrId,
        /// The requested number of active with scopes.
        scopes: usize,
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
    /// Lexical environment access failed.
    #[error("environment operation failed at node {id:?}: {source}")]
    Env {
        /// The node id associated with the environment operation.
        id: IrId,
        /// The underlying environment failure.
        source: EvalEnvError,
    },
    /// Thunk forcing failed.
    #[error("thunk force failed at node {id:?}: {source}")]
    Force {
        /// The node id associated with the force operation.
        id: IrId,
        /// The underlying force failure.
        source: ForceError,
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
    /// A flat attribute-set operation failed.
    #[error("attribute-set operation failed at node {id:?}: {source}")]
    Attr {
        /// The node id associated with the attrset operation.
        id: IrId,
        /// The underlying attrset failure.
        source: AttrError,
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
    /// An attribute selection found no binding and had no default.
    #[error("missing attribute {symbol:?} at node {id:?}")]
    MissingAttribute {
        /// The select node id.
        id: IrId,
        /// The missing static attribute symbol.
        symbol: Symbol,
    },
    /// A formal-set lambda argument missed a required attribute.
    #[error("missing required formal attribute {symbol:?} at node {id:?}")]
    MissingFormalAttribute {
        /// The application node id.
        id: IrId,
        /// The missing formal attribute symbol.
        symbol: Symbol,
    },
    /// A formal-set lambda argument carried an unexpected attribute.
    #[error("unexpected formal attribute {symbol:?} at node {id:?}")]
    UnexpectedFormalAttribute {
        /// The application node id.
        id: IrId,
        /// The unexpected argument attribute symbol.
        symbol: Symbol,
    },
    /// A dynamic with lookup found no attribute and no supported global fallback.
    #[error("unresolved with variable {symbol:?} at node {id:?}")]
    UnresolvedWithVar {
        /// The with-variable node id.
        id: IrId,
        /// The missing symbol.
        symbol: Symbol,
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
    /// A primitive operation exists in IR but is outside this evaluator slice.
    #[error("unsupported tree-walk primop symbol {symbol:?} at {id:?}")]
    UnsupportedPrimOp {
        /// The primop node id.
        id: IrId,
        /// The unsupported primop symbol.
        symbol: Symbol,
    },
    /// A primitive operation carries the wrong number of lowered arguments.
    #[error("invalid primop arity at {id:?}: expected {expected}, got {actual}")]
    InvalidPrimOpArity {
        /// The primop node id.
        id: IrId,
        /// The primop symbol whose argument list is malformed.
        symbol: Symbol,
        /// The expected number of arguments.
        expected: usize,
        /// The actual number of arguments in the IR child slice.
        actual: usize,
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
    /// An attribute path shape is outside the evaluator's supported access forms.
    #[error(
        "unsupported tree-walk attribute path {path:?} at {id:?}: segments={segments}, has_dynamic={has_dynamic}"
    )]
    UnsupportedAttrPath {
        /// The access node id.
        id: IrId,
        /// The unsupported attribute-path id.
        path: IrAttrPathId,
        /// The number of path segments.
        segments: usize,
        /// Whether any path segment is dynamic.
        has_dynamic: bool,
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
    use super::super::ThunkState;
    use super::*;
    use std::ptr::NonNull;

    use crate::compile::{
        EffectClass, FrameInfo, IrArena, IrBinding, IrData, IrInlineCacheSiteId, IrNode, IrShape,
        IrWithChain, lower as lower_ir, resolve as resolve_ast,
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

    fn eval_string_bytes(source: &str) -> Vec<u8> {
        let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
        let string = outcome
            .heap()
            .get_string(outcome.value())
            .expect("result is a heap-owned string");
        string.bytes().to_vec()
    }

    fn eval_list_string_bytes(source: &str) -> Vec<Vec<u8>> {
        let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("result is a heap-owned list");
        list.iter()
            .map(|value| {
                outcome
                    .heap()
                    .get_string(*value)
                    .expect("element is a heap-owned string")
                    .bytes()
                    .to_vec()
            })
            .collect()
    }

    fn eval_list_ints(source: &str) -> Vec<i64> {
        let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("result is a heap-owned list");
        list.iter()
            .map(|value| value.as_int().expect("element is an int"))
            .collect()
    }

    fn symbol_for(ir: &Ir, name: &[u8]) -> Symbol {
        let index = ir
            .symbols
            .symbols()
            .iter()
            .position(|symbol| symbol.as_slice() == name)
            .expect("symbol exists");
        Symbol::new(index as u32)
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

    fn manual_ir_with_with_chains(
        root: IrId,
        nodes: Vec<IrNode>,
        symbols: SymbolTable,
        with_chains: Vec<IrWithChain>,
    ) -> Ir {
        Ir {
            root,
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            symbols,
            frames: Vec::new().into_boxed_slice(),
            with_chains: with_chains.into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
    }

    fn manual_ir_with_attr_tables(
        root: IrId,
        nodes: Vec<IrNode>,
        symbols: SymbolTable,
        bindings: Vec<IrBinding>,
        shapes: Vec<IrShape>,
    ) -> Ir {
        Ir {
            root,
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            symbols,
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: bindings.into_boxed_slice(),
            shapes: shapes.into_boxed_slice(),
        }
    }

    fn manual_ir_with_attr_paths(
        root: IrId,
        nodes: Vec<IrNode>,
        symbols: SymbolTable,
        attr_paths: Vec<Box<[IrAttrPathSegment]>>,
    ) -> Ir {
        Ir {
            root,
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            symbols,
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: attr_paths.into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
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
    fn evaluates_uri_literals_as_strings() {
        assert_eq!(
            eval_string_bytes("https://example.test/path?x=1"),
            b"https://example.test/path?x=1"
        );
        assert_eq!(
            eval_string_bytes("https://example.test + \"/more\""),
            b"https://example.test/more"
        );
        assert_eq!(
            eval("https://example.test == \"https://example.test\"").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn unary_type_predicate_primops_classify_whnf_values() {
        assert_eq!(eval("builtins.isAttrs { a = 1; }").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isAttrs [ 1 ]").as_bool(), Ok(false));
        assert_eq!(eval("builtins.isList [ 1 ]").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isFunction (x: x)").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isString \"x\"").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isInt 1").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isInt 1.0").as_bool(), Ok(false));
        assert_eq!(eval("builtins.isFloat 1.0").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isBool false").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isNull null").as_bool(), Ok(true));
        assert_eq!(eval("isNull null").as_bool(), Ok(true));
        assert_eq!(
            eval("let isNull = x: false; in isNull null").as_bool(),
            Ok(false)
        );
        assert_eq!(eval("builtins.isPath \"not-path\"").as_bool(), Ok(false));
    }

    #[test]
    fn type_of_primop_returns_nix_type_names() {
        assert_eq!(eval_string_bytes("builtins.typeOf 1"), b"int");
        assert_eq!(eval_string_bytes("builtins.typeOf 1.0"), b"float");
        assert_eq!(eval_string_bytes("builtins.typeOf false"), b"bool");
        assert_eq!(eval_string_bytes("builtins.typeOf null"), b"null");
        assert_eq!(eval_string_bytes("builtins.typeOf \"x\""), b"string");
        assert_eq!(eval_string_bytes("builtins.typeOf [ 1 ]"), b"list");
        assert_eq!(eval_string_bytes("builtins.typeOf { a = 1; }"), b"set");
        assert_eq!(eval_string_bytes("builtins.typeOf (x: x)"), b"lambda");
    }

    #[test]
    fn length_primop_returns_list_spine_length_without_forcing_elements() {
        assert_eq!(eval("builtins.length []").as_int(), Ok(0));
        assert_eq!(eval("builtins.length [ 1 (1 / 0) true ]").as_int(), Ok(3));
        assert_eq!(
            eval("let builtins = { length = x: 42; }; in builtins.length [ 1 ]").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn length_primop_type_checks_argument() {
        let ir = lower("builtins.length 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("length requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn attr_names_primop_returns_sorted_names_without_forcing_values() {
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames { z = 1 / 0; a = 2; b = true; }"),
            vec![b"a".to_vec(), b"b".to_vec(), b"z".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames { a = 1; A = 1; aa = 1; _ = 1; }"),
            vec![b"A".to_vec(), b"_".to_vec(), b"a".to_vec(), b"aa".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes(
                "let builtins = { attrNames = x: [ \"local\" ]; }; in builtins.attrNames { a = 1; }"
            ),
            vec![b"local".to_vec()]
        );
    }

    #[test]
    fn attr_names_primop_type_checks_argument() {
        let ir = lower("builtins.attrNames 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("attrNames requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn attr_values_primop_returns_sorted_values_without_forcing_them() {
        let ir = lower("builtins.attrValues { z = 1 / 0; a = 2; }");
        let span = ir.arena.node(ir.root).expect("root exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator.eval_root().expect("attrValues evaluates");
        let values = {
            let list = evaluator
                .heap
                .get_list(value)
                .expect("result is a heap-owned list");
            list.as_slice().to_vec()
        };

        assert_eq!(values.len(), 2);
        let first = evaluator
            .force_value(ir.root, span, values[0])
            .expect("first value forces");
        assert_eq!(first.as_int(), Ok(2));
        let lazy_division = values[1];
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(lazy_division)
            .expect("second value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );

        assert_eq!(
            eval_list_string_bytes(
                "let builtins = { attrValues = x: [ \"local\" ]; }; in builtins.attrValues { a = 1; }"
            ),
            vec![b"local".to_vec()]
        );
    }

    #[test]
    fn attr_values_primop_type_checks_argument() {
        let ir = lower("builtins.attrValues 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("attrValues requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn tail_primop_returns_tail_without_forcing_elements() {
        let ir = lower("builtins.tail [ 1 (1 / 0) true ]");
        let outcome = eval_whnf_owned(&ir).expect("tail evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("tail result is heap-owned");

        assert_eq!(list.len(), 2);
        let lazy_division = list.get(0).expect("first tail element");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("first tail element remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
        assert_eq!(
            list.get(1).expect("second tail element").as_bool(),
            Ok(true)
        );

        assert_eq!(
            eval_list_string_bytes(
                "let builtins = { tail = x: [ \"local\" ]; }; in builtins.tail [ 1 ]"
            ),
            vec![b"local".to_vec()]
        );
    }

    #[test]
    fn tail_primop_rejects_empty_lists() {
        let ir = lower("builtins.tail []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("tail requires a non-empty list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::EmptyListPrimOp {
                id: argument,
                op: "tail"
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn tail_primop_type_checks_argument() {
        let ir = lower("builtins.tail 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("tail requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn function_args_primop_describes_lambda_formals_without_forcing_defaults() {
        let simple = eval_whnf_owned(&lower("builtins.functionArgs (x: x)"))
            .expect("functionArgs evaluates");
        let attrs = simple
            .heap()
            .get_attrs(simple.value())
            .expect("simple lambda result is attrs");
        assert!(attrs.is_empty());

        let ir = lower("builtins.functionArgs ({ b ? (1 / 0), a, ... }@args: a)");
        let outcome = eval_whnf_owned(&ir).expect("functionArgs evaluates");
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("formal-set lambda result is attrs");
        let entries = attrs
            .iter_lexicographic()
            .map(|entry| {
                (
                    ir.symbols
                        .resolve(entry.key)
                        .expect("entry key resolves")
                        .to_vec(),
                    entry.value.as_bool().expect("entry value is bool"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![(b"a".to_vec(), false), (b"b".to_vec(), true)]);
        assert_eq!(
            eval("let r = builtins.functionArgs ({ b ? (1 / 0), a }: a); in r.a == false && r.b")
                .as_bool(),
            Ok(true)
        );

        assert_eq!(
            eval("let builtins = { functionArgs = f: { local = true; }; }; in (builtins.functionArgs (x: x)).local")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn function_args_primop_type_checks_argument() {
        let ir = lower("builtins.functionArgs 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("functionArgs requires a lambda");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "function",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn list_to_attrs_primop_builds_attrs_with_first_wins_duplicates() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.listToAttrs [ { name = \"b\"; value = 1; } { name = \"a\"; value = 2; } ])"
            ),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(
            eval("(builtins.listToAttrs [ { name = \"a\"; value = 1; } { name = \"a\"; value = 1 / 0; } ]).a")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("(builtins.listToAttrs [ { name = \"a\"; value = 1; } { name = \"a\"; } ]).a")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let builtins = { listToAttrs = list: { local = true; }; }; in (builtins.listToAttrs []).local")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.listToAttrs [ { name = \"a\"; value = 1 / 0; } ]");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("listToAttrs primop evaluates");
        let attrs = evaluator
            .heap
            .get_attrs(value)
            .expect("listToAttrs result is attrs");
        let entry = attrs
            .iter_lexicographic()
            .next()
            .expect("listToAttrs result has one attr");
        assert_eq!(ir.symbols.resolve(entry.key), Some(b"a".as_slice()));
        let value = entry.value;
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("attribute value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn list_to_attrs_primop_type_checks_list_elements_and_names() {
        let ir = lower("builtins.listToAttrs 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("listToAttrs requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.listToAttrs [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("listToAttrs requires element attrsets");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.listToAttrs [ { name = 1; value = 2; } ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("listToAttrs requires string names");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn list_to_attrs_primop_reports_missing_name_value_pairs() {
        let ir = lower("builtins.listToAttrs [ {} ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let mut evaluator = TreeWalk::new(&ir);

        let error = evaluator
            .eval_root()
            .expect_err("listToAttrs requires a name attribute");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected missing name attribute");
        };
        assert_eq!(id, argument);
        assert_eq!(evaluator.symbols.resolve(symbol), Some(b"name".as_slice()));

        let ir = lower("builtins.listToAttrs [ { name = \"a\"; } ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let mut evaluator = TreeWalk::new(&ir);

        let error = evaluator
            .eval_root()
            .expect_err("listToAttrs requires a value attribute");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected missing value attribute");
        };
        assert_eq!(id, argument);
        assert_eq!(evaluator.symbols.resolve(symbol), Some(b"value".as_slice()));
    }

    #[test]
    fn concat_lists_primop_flattens_spines_without_forcing_elements() {
        assert_eq!(
            eval_list_ints("builtins.concatLists [ [ 1 ] [] [ 2 3 ] ]"),
            vec![1, 2, 3]
        );
        assert_eq!(eval_list_ints("builtins.concatLists []"), Vec::<i64>::new());

        let ir = lower("builtins.concatLists [ [ true (1 / 0) ] [] ]");
        let outcome = eval_whnf_owned(&ir).expect("concatLists evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("concatLists result is a list");

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
        let lazy_division = list.get(1).expect("second");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("inner list element remains lazy");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn concat_lists_primop_type_checks_outer_and_inner_lists() {
        let ir = lower("builtins.concatLists 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("concatLists requires an outer list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.concatLists [ [ 1 ] 2 [ 3 ] ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("concatLists requires inner lists");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.concatLists (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];

        let error = eval_whnf_owned(&ir).expect_err("outer list is forced first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );

        let ir = lower("builtins.concatLists [ [ 1 ] (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("inner lists are forced in order");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn head_primop_returns_first_element_without_forcing_list_elements() {
        let ir = lower("builtins.head [ (1 / 0) true ]");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("head primop evaluates");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("head result remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );

        assert_eq!(eval("builtins.head [ true (1 / 0) ]").as_bool(), Ok(true));
        assert_eq!(
            eval_string_bytes("let builtins = { head = x: \"local\"; }; in builtins.head [ 1 ]"),
            b"local"
        );
    }

    #[test]
    fn head_primop_rejects_empty_lists() {
        let ir = lower("builtins.head []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("head requires a non-empty list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::EmptyListPrimOp {
                id: argument,
                op: "head"
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn head_primop_type_checks_argument() {
        let ir = lower("builtins.head 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("head requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn elem_at_primop_returns_indexed_element_without_forcing_other_elements() {
        assert_eq!(
            eval("builtins.elemAt [ true (1 / 0) false ] 0").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let builtins = { elemAt = xs: n: 42; }; in builtins.elemAt [ true ] 0").as_int(),
            Ok(42)
        );

        let ir = lower("builtins.elemAt [ true (1 / 0) false ] 1");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("elemAt primop evaluates");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected element remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn elem_at_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.elemAt 1 true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt checks the index before the list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: index,
                expected: "int",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), index_span);

        let ir = lower("builtins.elemAt (1 / 0) true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt checks index type before forcing list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: index,
                expected: "int",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), index_span);

        let ir = lower("builtins.elemAt 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt forces the index before checking the list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: index }
        );
        assert_eq!(error.span(), index_span);

        let ir = lower("builtins.elemAt [] true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt requires an integer index");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: index,
                expected: "int",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), index_span);
    }

    #[test]
    fn elem_at_primop_rejects_out_of_range_indexes() {
        for (source, expected_index) in [
            ("builtins.elemAt [ true ] 1", 1),
            ("builtins.elemAt [ true ] (-1)", -1),
        ] {
            let ir = lower(source);
            let root = ir.arena.node(ir.root).expect("root exists");
            let IrData::PrimOp { args, .. } = root.data else {
                panic!("root is a primop");
            };
            let args = ir.arena.child_slice(args).expect("primop args exist");
            let index = args[1];
            let index_span = ir.arena.node(index).expect("index argument exists").span;

            let error = eval_whnf(&ir).expect_err("elemAt requires an in-range index");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index,
                    index: expected_index,
                    len: 1
                }
            );
            assert_eq!(error.span(), index_span);
        }
    }

    #[test]
    fn elem_primop_scans_list_with_structural_equality() {
        assert_eq!(eval("builtins.elem 2 [ 1 2 (1 / 0) ]").as_bool(), Ok(true));
        assert_eq!(eval("builtins.elem 3 [ 1 2 ]").as_bool(), Ok(false));
        assert_eq!(
            eval("builtins.elem { a = 1; } [ { a = 1; } { a = 1 / 0; } ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = x: x; in builtins.elem f [ f ]").as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins.elem (x: x) [ (x: x) ]").as_bool(), Ok(false));
        assert_eq!(
            eval("let v = { a = x: x; }; in builtins.elem v.a [ v.a ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let xs = [ xs ]; in builtins.elem xs xs").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let s = rec { a = s; }; in builtins.elem s [ s ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let xs = [ (1 / 0) ]; in builtins.elem xs [ xs ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(
                "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in builtins.elem nan [ nan ]"
            )
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(
                "builtins.elem ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
        assert_eq!(eval("builtins.elem (1 / 0) []").as_bool(), Ok(false));
        assert_eq!(
            eval("let builtins = { elem = value: list: false; }; in builtins.elem 1 [ 1 ]")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn elem_primop_type_checks_list_before_candidate() {
        let ir = lower("builtins.elem (1 / 0) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("elem checks list type before candidate");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.elem 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("elem forces the list before the candidate");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.elem 2 [ 1 (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("elem scans until match or error");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("let x = 1 / 0; in builtins.elem x [ x ]");
        let error = eval_whnf_owned(&ir).expect_err("elem forces shared throwing candidates");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("let s = { x = 1 / 0; }; v = { a = s; }; in builtins.elem v.a [ v.a ]");
        let error = eval_whnf_owned(&ir).expect_err("elem does not hide selected attrset errors");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn less_than_primop_uses_language_comparison_semantics() {
        assert_eq!(eval("builtins.lessThan 1 2").as_bool(), Ok(true));
        assert_eq!(eval("builtins.lessThan 2 1").as_bool(), Ok(false));
        assert_eq!(eval("builtins.lessThan 1 1").as_bool(), Ok(false));
        assert_eq!(eval("builtins.lessThan 1 1.5").as_bool(), Ok(true));
        assert_eq!(eval("builtins.lessThan \"a\" \"b\"").as_bool(), Ok(true));
        assert_eq!(
            eval("builtins.lessThan [ 1 2 ] [ 1 3 ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.lessThan [ 1 (1 / 0) ] [ 2 (1 / 0) ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let builtins = { lessThan = left: right: false; }; in builtins.lessThan 1 2")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn less_than_primop_forces_operands_before_type_checks() {
        let ir = lower("builtins.lessThan true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("lessThan forces rhs before type check");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.lessThan true false");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let lhs = args[0];
        let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&ir).expect_err("lessThan rejects incomparable lhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number, string, or list",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), lhs_span);

        let ir = lower("builtins.lessThan 1 true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("lessThan checks rhs against lhs type");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.lessThan [ 1 (1 / 0) ] [ 1 2 ]");
        let error = eval_whnf_owned(&ir).expect_err("equal list prefix forces next element");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn arithmetic_primops_use_numeric_semantics() {
        assert_eq!(eval("builtins.add 1 2").as_int(), Ok(3));
        assert_eq!(eval("builtins.sub 5 8").as_int(), Ok(-3));
        assert_eq!(eval("builtins.mul 2 3").as_int(), Ok(6));
        assert_eq!(eval("builtins.div 7 2").as_int(), Ok(3));
        assert_eq!(eval("builtins.add 1 2.5").as_float(), Ok(3.5));
        assert_eq!(eval("builtins.sub 1 2.5").as_float(), Ok(-1.5));
        assert_eq!(eval("builtins.mul 2 0.5").as_float(), Ok(1.0));
        assert_eq!(eval("builtins.div 7 2.0").as_float(), Ok(3.5));
        assert_eq!(
            eval("builtins.add 9223372036854775807 1").as_int(),
            Ok(i64::MIN)
        );
        assert_eq!(eval("builtins.mul 9223372036854775807 2").as_int(), Ok(-2));
    }

    #[test]
    fn arithmetic_primops_are_strict_and_numeric_only() {
        let ir = lower("builtins.add \"a\" (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins before type check");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.add \"a\" \"b\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let lhs = args[0];
        let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("strings are invalid for builtins.add");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let ir = lower("builtins.sub true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("sub forces rhs before lhs type check");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let div_zero = lower("builtins.div 1 0");
        let error = eval_whnf(&div_zero).expect_err("integer division by zero is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: div_zero.root }
        );

        let div_overflow = lower("builtins.div (-9223372036854775807 - 1) (-1)");
        let error = eval_whnf(&div_overflow).expect_err("integer division overflow is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ArithmeticOverflow {
                id: div_overflow.root,
                op: ArithmeticOp::Div,
            }
        );
    }

    #[test]
    fn bitwise_primops_apply_signed_integer_ops() {
        assert_eq!(eval("builtins.bitAnd 6 3").as_int(), Ok(2));
        assert_eq!(eval("builtins.bitOr 4 1").as_int(), Ok(5));
        assert_eq!(eval("builtins.bitXor 6 3").as_int(), Ok(5));
        assert_eq!(eval("builtins.bitXor (-1) 1").as_int(), Ok(-2));
        assert_eq!(
            eval("let builtins = { bitAnd = left: right: 42; }; in builtins.bitAnd 6 3").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn bitwise_primops_type_check_arguments_left_to_right() {
        let ir = lower("builtins.bitAnd true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let lhs = args[0];
        let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&ir).expect_err("bitAnd checks lhs before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "int",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let ir = lower("builtins.bitAnd 1 true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("bitAnd checks rhs after valid lhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "int",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.bitAnd 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("bitAnd forces rhs after valid lhs");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn get_attr_primop_returns_attr_without_forcing_selected_value() {
        assert_eq!(
            eval("builtins.getAttr \"a\" { a = 1; b = 1 / 0; }").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let builtins = { getAttr = name: set: 42; }; in builtins.getAttr \"a\" {}")
                .as_int(),
            Ok(42)
        );

        let ir = lower("builtins.getAttr \"a\" { a = 1 / 0; }");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("getAttr primop evaluates");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected attr remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn get_attr_primop_reports_missing_attrs() {
        let ir = lower("builtins.getAttr \"missing\" { a = 1; }");
        let root = ir.arena.node(ir.root).expect("root exists");

        let error = eval_whnf(&ir).expect_err("getAttr requires the attribute to exist");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected a missing attribute error");
        };
        assert_eq!(id, ir.root);
        assert_eq!(ir.symbols.resolve(symbol), Some(b"missing".as_slice()));
        assert_eq!(error.span(), root.span);
    }

    #[test]
    fn get_attr_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.getAttr 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let name = args[0];
        let name_span = ir.arena.node(name).expect("name argument exists").span;

        let error = eval_whnf(&ir).expect_err("getAttr checks the name before the attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: name,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), name_span);

        let ir = lower("builtins.getAttr \"a\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let attrs = args[1];
        let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

        let error = eval_whnf(&ir).expect_err("getAttr requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: attrs,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), attrs_span);
    }

    #[test]
    fn has_attr_primop_reports_presence_without_forcing_values() {
        assert_eq!(
            eval("builtins.hasAttr \"a\" { a = 1 / 0; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.hasAttr \"b\" { a = 1 / 0; }").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let builtins = { hasAttr = name: set: false; }; in builtins.hasAttr \"a\" { a = true; }")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn has_attr_primop_type_checks_name_before_attrset() {
        let ir = lower("builtins.hasAttr 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let name = args[0];
        let name_span = ir.arena.node(name).expect("name argument exists").span;

        let error = eval_whnf(&ir).expect_err("hasAttr checks the name before the attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: name,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), name_span);

        let ir = lower("builtins.hasAttr \"a\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let attrs = args[1];
        let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

        let error = eval_whnf(&ir).expect_err("hasAttr requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: attrs,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), attrs_span);
    }

    #[test]
    fn remove_attrs_primop_removes_names_without_forcing_values() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.removeAttrs { z = 1; a = 1 / 0; b = 2; } [ \"z\" \"missing\" \"z\" ])"
            ),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(
            eval("let r = builtins.removeAttrs { a = 1 / 0; b = 2; } [ \"a\" ]; in r.b").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let builtins = { removeAttrs = set: names: { local = true; }; }; in (builtins.removeAttrs {} []).local")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn remove_attrs_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.removeAttrs 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let attrs = args[0];
        let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

        let error = eval_whnf(&ir).expect_err("removeAttrs checks the attrset before names");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: attrs,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), attrs_span);

        let ir = lower("builtins.removeAttrs {} 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let names = args[1];
        let names_span = ir.arena.node(names).expect("names argument exists").span;

        let error = eval_whnf(&ir).expect_err("removeAttrs requires a name list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: names,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), names_span);

        let ir = lower("builtins.removeAttrs {} [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let names = args[1];
        let names_span = ir.arena.node(names).expect("names argument exists").span;

        let error = eval_whnf(&ir).expect_err("removeAttrs requires string names");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: names,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), names_span);
    }

    #[test]
    fn intersect_attrs_primop_takes_names_from_left_and_values_from_right() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.intersectAttrs { z = 1; a = 1 / 0; b = 3; } { z = 4; a = 5; c = 6; })"
            ),
            vec![b"a".to_vec(), b"z".to_vec()]
        );
        assert_eq!(
            eval("let r = builtins.intersectAttrs { a = 1 / 0; } { a = 2; }; in r.a").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let builtins = { intersectAttrs = left: right: { local = true; }; }; in (builtins.intersectAttrs {} {}).local")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.intersectAttrs { a = 1; } { a = 1 / 0; }");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("intersectAttrs primop evaluates");
        let attrs = evaluator
            .heap
            .get_attrs(value)
            .expect("intersectAttrs result is attrs");
        let entry = attrs
            .iter_lexicographic()
            .next()
            .expect("intersectAttrs result has one attr");
        assert_eq!(ir.symbols.resolve(entry.key), Some(b"a".as_slice()));
        let value = entry.value;
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected right value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn intersect_attrs_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.intersectAttrs 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let left = args[0];
        let left_span = ir.arena.node(left).expect("left argument exists").span;

        let error = eval_whnf(&ir).expect_err("intersectAttrs checks the left set first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: left,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), left_span);

        let ir = lower("builtins.intersectAttrs {} 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let right = args[1];
        let right_span = ir.arena.node(right).expect("right argument exists").span;

        let error = eval_whnf(&ir).expect_err("intersectAttrs requires a right attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: right,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), right_span);
    }

    #[test]
    fn cat_attrs_primop_collects_present_attrs_in_list_order() {
        let outcome = eval_whnf_owned(&lower(
            "builtins.catAttrs \"a\" [ { a = 1; } { b = 1 / 0; } { a = 2; } ]",
        ))
        .expect("catAttrs evaluates");
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("catAttrs returns a list");

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
        assert_eq!(list.get(1).expect("second").as_int(), Ok(2));
        let shadowed = eval_whnf_owned(&lower(
            "let builtins = { catAttrs = name: list: [ true ]; }; in builtins.catAttrs \"a\" []",
        ))
        .expect("shadowed catAttrs evaluates");
        let shadowed_list = shadowed
            .heap()
            .get_list(shadowed.value())
            .expect("shadowed catAttrs returns a list");
        assert_eq!(
            shadowed_list.get(0).expect("first local value").as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.catAttrs \"a\" [ { a = 1 / 0; } { b = 2; } ]");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("catAttrs primop evaluates");
        let list = evaluator
            .heap
            .get_list(value)
            .expect("catAttrs returns a heap-owned list");
        assert_eq!(list.len(), 1);
        let value = list.get(0).expect("selected attr exists");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected attr value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn cat_attrs_primop_type_checks_arguments_and_elements_in_order() {
        let ir = lower("builtins.catAttrs 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let name = args[0];
        let name_span = ir.arena.node(name).expect("name argument exists").span;

        let error = eval_whnf(&ir).expect_err("catAttrs checks the name before the list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: name,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), name_span);

        let ir = lower("builtins.catAttrs \"a\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("catAttrs requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.catAttrs \"a\" [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("catAttrs requires attrset elements");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), list_span);
    }

    #[test]
    fn ceil_and_floor_primops_round_numbers_to_ints() {
        assert_eq!(eval("builtins.ceil 1").as_int(), Ok(1));
        assert_eq!(eval("builtins.ceil 1.2").as_int(), Ok(2));
        assert_eq!(eval("builtins.ceil (-1.2)").as_int(), Ok(-1));
        assert_eq!(eval("builtins.floor 1").as_int(), Ok(1));
        assert_eq!(eval("builtins.floor 1.8").as_int(), Ok(1));
        assert_eq!(eval("builtins.floor (-1.2)").as_int(), Ok(-2));
        assert_eq!(
            eval("let builtins = { ceil = x: 42; }; in builtins.ceil 1.2").as_int(),
            Ok(42)
        );
        assert_eq!(
            eval("let builtins = { floor = x: 42; }; in builtins.floor 1.8").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn ceil_and_floor_primops_type_check_arguments() {
        for source in ["builtins.ceil true", "builtins.floor true"] {
            let ir = lower(source);
            let root = ir.arena.node(ir.root).expect("root exists");
            let IrData::PrimOp { args, .. } = root.data else {
                panic!("root is a primop");
            };
            let args = ir.arena.child_slice(args).expect("primop args exist");
            let argument = args[0];
            let argument_span = ir.arena.node(argument).expect("argument exists").span;

            let error = eval_whnf(&ir).expect_err("rounding requires a number");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "number",
                    actual: ValueTag::Bool
                }
            );
            assert_eq!(error.span(), argument_span);
        }
    }

    #[test]
    fn ceil_and_floor_primops_saturate_int_range_boundaries() {
        for source in [
            "builtins.ceil 9223372036854775807.0",
            "builtins.ceil 9223372036854775808.0",
            "builtins.floor 9223372036854775807.0",
            "builtins.floor 9223372036854775808.0",
        ] {
            assert_eq!(eval(source).as_int(), Ok(i64::MAX));
        }
    }

    #[test]
    fn has_context_primop_reports_string_context_presence() {
        assert_eq!(eval("builtins.hasContext \"x\"").as_bool(), Ok(false));
        assert_eq!(
            eval("let builtins = { hasContext = x: true; }; in builtins.hasContext \"x\"")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.hasContext \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("hasContext argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"x".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        assert_eq!(
            evaluator
                .eval_has_context_primop(argument, argument_span, value)
                .expect("hasContext evaluates")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn has_context_primop_type_checks_argument() {
        let ir = lower("builtins.hasContext 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("hasContext requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn strict_unary_primops_force_arguments() {
        let ir = lower("builtins.isInt (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("predicate forces argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn unsupported_strict_primops_force_arguments_before_reporting_unsupported() {
        let ir = lower("builtins.getEnv (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("unsupported primop still forces argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn unsupported_primops_report_symbol_and_span() {
        let ir = lower("builtins.getEnv \"HOME\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { symbol, .. } = root.data else {
            panic!("root is a primop");
        };

        let error = eval_whnf_owned(&ir).expect_err("getEnv remains unsupported");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedPrimOp {
                id: ir.root,
                symbol,
            }
        );
        assert_eq!(error.span(), root.span);
    }

    #[test]
    fn interpolation_coerces_attrsets_with_to_string_before_out_path() {
        assert_eq!(
            eval_string_bytes("\"${{ __toString = self: self.name; name = \"custom\"; }}\""),
            b"custom"
        );
        assert_eq!(
            eval_string_bytes("\"pre-${{ outPath = \"store\"; }}-post\""),
            b"pre-store-post"
        );
        assert_eq!(
            eval_string_bytes("\"${{ __toString = self: \"hook\"; outPath = 1 / 0; }}\""),
            b"hook"
        );
        assert_eq!(
            eval_string_bytes("\"${{ __toString = self: { outPath = \"nested\"; }; }}\""),
            b"nested"
        );
        assert_eq!(
            eval_string_bytes("\"${{ outPath = { outPath = \"nested\"; }; }}\""),
            b"nested"
        );
    }

    #[test]
    fn dynamic_attr_names_use_string_coercion() {
        assert_eq!(
            eval("{ ${ { outPath = \"name\"; } } = 7; }.name").as_int(),
            Ok(7)
        );
        assert_eq!(
            eval("{ value = 9; }.${ { __toString = self: \"value\"; } }").as_int(),
            Ok(9)
        );
    }

    #[test]
    fn interpolation_rejects_non_coercible_values() {
        let cases = [
            ("\"${1}\"", ValueTag::Int),
            ("\"${true}\"", ValueTag::Bool),
            ("\"${null}\"", ValueTag::Null),
            ("\"${[]}\"", ValueTag::List),
            ("\"${{}}\"", ValueTag::Attrs),
        ];

        for (source, actual) in cases {
            let ir = lower(source);
            let error = eval_whnf_owned(&ir).expect_err("value is not interpolable");
            let TreeWalkErrorKind::Type {
                expected,
                actual: observed,
                ..
            } = error.kind()
            else {
                panic!("expected type error for {source}");
            };
            assert_eq!(expected, "string");
            assert_eq!(observed, actual);
        }
    }

    #[test]
    fn interpolation_requires_to_string_results_to_be_strings() {
        let ir = lower("\"${{ __toString = self: 1; }}\"");
        let error = eval_whnf_owned(&ir).expect_err("__toString result must be a string");
        let TreeWalkErrorKind::Type {
            expected, actual, ..
        } = error.kind()
        else {
            panic!("expected type error for non-string __toString result");
        };
        assert_eq!(expected, "string");
        assert_eq!(actual, ValueTag::Int);

        let ir = lower("\"${{ __toString = \"bad\"; outPath = \"fallback\"; }}\"");
        let error = eval_whnf_owned(&ir).expect_err("__toString takes precedence over outPath");
        let TreeWalkErrorKind::Type {
            expected, actual, ..
        } = error.kind()
        else {
            panic!("expected type error for non-lambda __toString");
        };
        assert_eq!(expected, "lambda");
        assert_eq!(actual, ValueTag::String);

        let ir = lower("\"${{ __toString = self: {}; outPath = \"fallback\"; }}\"");
        let error = eval_whnf_owned(&ir).expect_err("bad __toString result does not fall back");
        let TreeWalkErrorKind::Type {
            expected, actual, ..
        } = error.kind()
        else {
            panic!("expected type error for non-coercible __toString result");
        };
        assert_eq!(expected, "string");
        assert_eq!(actual, ValueTag::Attrs);
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
    fn evaluates_non_empty_list_literals_with_lazy_elements() {
        let ir = lower("[ true (1 / 0) \"s\" ]");
        let outcome = eval_whnf_owned(&ir).expect("non-empty list evaluates");
        let value = outcome.value();
        let heap = outcome.heap();
        let list = heap.get_list(value).expect("list is heap-owned");

        assert_eq!(value.tag(), ValueTag::List);
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));

        let lazy_division = list.get(1).expect("second");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("list element thunk is heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );

        let string = list.get(2).expect("third");
        assert_eq!(
            heap.get_string(string)
                .expect("string element is heap-owned")
                .bytes(),
            b"s"
        );
    }

    #[test]
    fn list_element_thunks_capture_let_environments() {
        let ir = lower("let x = 1 + 2; in [ x ]");
        let outcome = eval_whnf_owned(&ir).expect("list evaluates");
        let heap = outcome.heap();
        let list = heap.get_list(outcome.value()).expect("list is heap-owned");
        let element = list.get(0).expect("first");
        let element_thunk = heap
            .get_thunk(element)
            .expect("list element thunk is heap-owned");

        assert_eq!(element_thunk.env().frames().len(), 1);
        let captured_x = element_thunk.env().frames()[0]
            .get(0)
            .expect("captured frame slot exists");
        assert_eq!(captured_x.tag(), ValueTag::Thunk);
        let x_thunk = heap
            .get_thunk(captured_x)
            .expect("captured binding thunk is heap-owned");
        assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(x_thunk.body())
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
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
    fn list_concat_concatenates_non_empty_lists_without_forcing_elements() {
        let ir = lower("[ (1 / 0) ] ++ [ true ]");
        let outcome = eval_whnf_owned(&ir).expect("list concat evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("concat result is heap-owned");

        assert_eq!(list.len(), 2);
        let lazy_division = list.get(0).expect("first");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("left element thunk is heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
        assert_eq!(list.get(1).expect("second").as_bool(), Ok(true));
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
    fn attr_update_merges_shallowly_with_rhs_precedence() {
        assert_eq!(
            eval("let r = { a = 1; } // { b = 2; }; in r.a + r.b").as_int(),
            Ok(3)
        );
        assert_eq!(eval("(({ a = 1 / 0; } // { a = 2; }).a)").as_int(), Ok(2));
        assert_eq!(
            eval("(({ a = { x = 1; }; } // { a = { y = 2; }; }).a.x or 9)").as_int(),
            Ok(9)
        );
    }

    #[test]
    fn attr_update_keeps_values_lazy() {
        assert_eq!(
            eval("let r = { a = 1; } // { b = 1 / 0; }; in r.a").as_int(),
            Ok(1)
        );

        let ir = lower("{ a = 1 / 0; } // { b = 2; }");
        let a = symbol_for(&ir, b"a");
        let b = symbol_for(&ir, b"b");
        let outcome = eval_whnf_owned(&ir).expect("attr update evaluates");
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("update result is heap-owned");

        assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(2));
        let lazy_division = attrs.get(a).expect("a exists");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = outcome
            .heap()
            .get_thunk(lazy_division)
            .expect("left attr value stays lazy");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    }

    #[test]
    fn evaluates_empty_attrsets_with_owned_heap() {
        let ir = lower("{}");
        let outcome = eval_whnf_owned(&ir).expect("empty attrset evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::Attrs);
        assert!(
            outcome
                .heap()
                .get_attrs(value)
                .expect("attrset is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn evaluates_static_attrsets_with_lazy_values() {
        let ir = lower("{ a = 1; b = (1 / 0); }");
        let a = symbol_for(&ir, b"a");
        let b = symbol_for(&ir, b"b");
        let outcome = eval_whnf_owned(&ir).expect("static attrset evaluates");
        let heap = outcome.heap();
        let attrs = heap
            .get_attrs(outcome.value())
            .expect("attrset is heap-owned");

        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs.get(a).expect("a exists").as_int(), Ok(1));

        let lazy_division = attrs.get(b).expect("b exists");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("attr value thunk is heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena.node(thunk.body()).expect("thunk body exists").kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn evaluates_static_recursive_attrsets_with_lazy_self_scope() {
        assert_eq!(eval("(rec { a = 1; b = a + 2; }).b").as_int(), Ok(3));
        assert_eq!(eval("(rec { a = b; b = 1; }).a").as_int(), Ok(1));
        assert_eq!(eval("(rec { a = 1 / 0; }).b or 2").as_int(), Ok(2));

        let ir = lower("(rec { a = a; }).a");
        let error = eval_whnf(&ir).expect_err("recursive attr self-reference blackholes");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Force {
                source: ForceError::InfiniteRecursion,
                ..
            }
        ));
    }

    #[test]
    fn forcing_attr_value_thunks_memoizes_whnf_results() {
        let ir = lower("{ a = 1 + 2; }");
        let a = symbol_for(&ir, b"a");
        let mut evaluator = TreeWalk::new(&ir);
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };

        assert_eq!(thunk_value.tag(), ValueTag::Thunk);
        assert_eq!(
            evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("thunk exists")
                .cell()
                .state(),
            Ok(ThunkState::Suspended)
        );

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("thunk remains heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
        let cached = thunk
            .cell()
            .cached_value()
            .expect("forced thunk has cached value")
            .expect("cached value exists");
        assert!(cached.raw_eq(Value::int(3)));

        let forced_again = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("forced thunk reuses cache");
        assert_eq!(forced_again.as_int(), Ok(3));
    }

    #[test]
    fn strict_operand_evaluation_forces_direct_thunk_alloc_results() {
        let body = IrId::new(0);
        let lhs = IrId::new(1);
        let rhs = IrId::new(2);
        let root = IrId::new(3);
        let ir = manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(IrKind::ThunkAlloc, Span::new(0, 1), IrData::Node(body)),
                pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(2)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(0, 5),
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs,
                        rhs,
                    },
                ),
            ],
        );

        assert_eq!(
            eval_whnf(&ir)
                .expect("strict operand thunk is forced")
                .as_int(),
            Ok(3)
        );
    }

    #[test]
    fn forcing_errors_reset_thunks_to_suspended() {
        let ir = lower("{ a = 1 / 0; }");
        let a = symbol_for(&ir, b"a");
        let mut evaluator = TreeWalk::new(&ir);
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let error = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect_err("division by zero remains a force error");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("thunk remains heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert!(
            thunk
                .cell()
                .cached_value()
                .expect("suspended thunk has no invalid state")
                .is_none()
        );
    }

    #[test]
    fn evaluates_dynamic_attrsets_with_string_keys_and_null_omission() {
        assert_eq!(
            eval("let name = \"a\"; in { ${name} = 1; }.${name}").as_int(),
            Ok(1)
        );
        assert_eq!(eval("({ ${\"a\" + \"b\"} = 3; }).ab").as_int(), Ok(3));
        assert_eq!(eval("rec { ${\"a\"} = b; b = 2; }.a").as_int(), Ok(2));
        assert_eq!(
            eval("let a = 7; in rec { ${\"x\"} = a; a = 1; }.x").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval(
                "let x = \"x\"; y = \"outer\"; in rec { ${y} = 1; a = \"bar\"; b = \"baz\"; }.outer"
            )
            .as_int(),
            Ok(1)
        );
        assert_eq!(eval("{ ${null} = 1 / 0; a = 2; }.a").as_int(), Ok(2));

        let skipped = lower("{ ${null} = 1 / 0; }");
        let outcome = eval_whnf_owned(&skipped).expect("null dynamic key is skipped");
        assert!(
            outcome
                .heap()
                .get_attrs(outcome.value())
                .expect("attrset is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn dynamic_attrsets_report_duplicate_and_non_string_keys() {
        let duplicate = lower("{ ${\"a\"} = 1; a = 2; }");
        let duplicate_symbol = symbol_for(&duplicate, b"a");
        let duplicate_error =
            eval_whnf_owned(&duplicate).expect_err("computed duplicate key is invalid");
        assert_eq!(
            duplicate_error.kind(),
            TreeWalkErrorKind::Attr {
                id: duplicate.root,
                source: AttrError::DuplicateKey {
                    key: duplicate_symbol
                },
            }
        );

        let non_string = lower("{ ${1} = 1; }");
        let expression = non_string
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| node.kind == IrKind::Int && node.data == IrData::Int(1))
            .map(|(index, _)| IrId::new(index as u32))
            .expect("dynamic key expression exists");
        let error = eval_whnf_owned(&non_string).expect_err("dynamic key must be string or null");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: expression,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(
            error.span(),
            non_string
                .arena
                .node(expression)
                .expect("dynamic key expression exists")
                .span
        );
    }

    #[test]
    fn let_bindings_are_lazy_and_self_visible() {
        assert_eq!(eval("let x = 1 + 2; in x").as_int(), Ok(3));
        assert_eq!(eval("let a = 1; b = 2; in a + b").as_int(), Ok(3));
        assert_eq!(
            eval("let a = 1; b = 2; in let c = a + b; in c").as_int(),
            Ok(3)
        );
        assert_eq!(eval("let x = 1 / 0; in 7").as_int(), Ok(7));
        assert_eq!(eval("let p = ./foo; in 7").as_int(), Ok(7));

        let ir = lower("let x = x; in x");
        let error = eval_whnf(&ir).expect_err("self-recursive let blackholes");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Force {
                source: ForceError::InfiniteRecursion,
                ..
            }
        ));
    }

    #[test]
    fn let_environment_captures_survive_escaping_thunks() {
        assert_eq!(eval("(let x = 1 + 2; in { a = x; }).a").as_int(), Ok(3));
        assert_eq!(eval("let x = 1; in let y = x + 2; in y").as_int(), Ok(3));
    }

    #[test]
    fn simple_lambdas_apply_with_lazy_arguments() {
        assert_eq!(eval("(x: x + 1) 2").as_int(), Ok(3));
        assert_eq!(eval("let f = x: x; in f (1 + 2)").as_int(), Ok(3));
        assert_eq!(eval("let f = x: 7; in f (1 / 0)").as_int(), Ok(7));
        assert_eq!(eval("let x = 1; f = y: x + y; in f 2").as_int(), Ok(3));
        assert_eq!(
            eval("let x = 1; f = y: x + y; in let x = 10; in f x").as_int(),
            Ok(11)
        );
        assert_eq!(eval("((x: y: x) (1 + 2)) 0").as_int(), Ok(3));
    }

    #[test]
    fn with_scopes_probe_dynamic_attrs_lazily() {
        assert_eq!(eval("with { a = 1; }; a").as_int(), Ok(1));
        assert_eq!(eval("with { f = x: x + 1; }; f 2").as_int(), Ok(3));
        assert_eq!(eval("with (1 / 0); 7").as_int(), Ok(7));
        assert_eq!(eval("with { a = 1 / 0; }; 7").as_int(), Ok(7));
        assert_eq!(eval("with { a = 1; }; with { a = 2; }; a").as_int(), Ok(2));
        assert_eq!(eval("let a = 3; in with { a = 1; }; a").as_int(), Ok(3));
        assert_eq!(eval("with { true = 1; }; true").as_int(), Ok(1));
        assert_eq!(eval("with {}; true").as_bool(), Ok(true));
        assert_eq!(eval("with {}; false").as_bool(), Ok(false));
        assert_eq!(eval("with {}; null").tag(), ValueTag::Null);
    }

    #[test]
    fn with_scopes_capture_lexical_environments() {
        assert_eq!(
            eval("let x = 1; f = y: with { a = x + y; }; a; in let x = 10; in f x").as_int(),
            Ok(11)
        );
        assert_eq!(
            eval("let x = 1; scope = { a = x; }; f = y: with scope; a + y; in f 2").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("let f = with { a = 1; }; x: a + x; in f 2").as_int(),
            Ok(3)
        );
        assert_eq!(eval("(with { a = 1 + 2; }; { b = a; }).b").as_int(), Ok(3));
    }

    #[test]
    fn with_lookup_reports_non_attr_scopes_and_missing_names() {
        let non_attr = lower("with 1; missing");
        let root = non_attr.arena.node(non_attr.root).expect("root exists");
        let IrData::Pair { first, .. } = root.data else {
            panic!("with root has pair payload");
        };
        let first_span = non_attr.arena.node(first).expect("scope exists").span;
        let error = eval_whnf(&non_attr).expect_err("non-attr with scope is invalid on lookup");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), first_span);

        let missing = lower("with {}; missing");
        let IrData::Pair {
            second: missing_var,
            ..
        } = missing
            .arena
            .node(missing.root)
            .expect("missing root exists")
            .data
        else {
            panic!("with root has pair payload");
        };
        let missing_symbol = symbol_for(&missing, b"missing");
        let error = eval_whnf(&missing).expect_err("missing with name remains unresolved");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnresolvedWithVar {
                id: missing_var,
                symbol: missing_symbol,
            }
        );
    }

    #[test]
    fn formal_set_lambdas_bind_attrs_defaults_ellipsis_and_aliases() {
        assert_eq!(eval("({ x }: x) { x = 1; }").as_int(), Ok(1));
        assert_eq!(eval("({ x, y }: x + y) { x = 1; y = 2; }").as_int(), Ok(3));
        assert_eq!(
            eval("({ x, ... }: x) { x = 1; y = 1 / 0; }").as_int(),
            Ok(1)
        );
        assert_eq!(eval("({ x ? 1 + 2 }: x) {}").as_int(), Ok(3));
        assert_eq!(eval("({ x ? 1 / 0 }: 7) {}").as_int(), Ok(7));
        assert_eq!(eval("({ x ? 1 / 0 }: x) { x = 7; }").as_int(), Ok(7));
        assert_eq!(eval("({ a, b ? a + 1 }: b) { a = 2; }").as_int(), Ok(3));
        assert_eq!(
            eval("(args@{ x, ... }: args.x) { x = 1; y = 2; }").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("({ x, ... }@args: args.y) { x = 1; y = 2; }").as_int(),
            Ok(2)
        );
        assert_eq!(eval("({ x ? 1 }@args: args ? x) {}").as_bool(), Ok(false));
        assert_eq!(
            eval("({ x ? 1 }@args: args ? x) { x = 2; }").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn formal_set_lambdas_report_match_errors() {
        let missing = lower("({ x }: x) {}");
        let missing_symbol = symbol_for(&missing, b"x");
        let error = eval_whnf(&missing).expect_err("required formal is missing");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingFormalAttribute {
                id: missing.root,
                symbol: missing_symbol,
            }
        );

        let extra = lower("({ x }: x) { x = 1; z = 2; a = 3; }");
        let extra_symbol = symbol_for(&extra, b"a");
        let error = eval_whnf(&extra).expect_err("extra attr without ellipsis is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnexpectedFormalAttribute {
                id: extra.root,
                symbol: extra_symbol,
            }
        );

        let non_attr = lower("({ x }: x) 1");
        let root = non_attr.arena.node(non_attr.root).expect("root exists");
        let IrData::Pair { second, .. } = root.data else {
            panic!("application root has pair payload");
        };
        let second_span = non_attr.arena.node(second).expect("argument exists").span;
        let error = eval_whnf(&non_attr).expect_err("formal-set argument must be attrs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: second,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), second_span);
    }

    #[test]
    fn function_application_requires_lambda_functions() {
        let ir = lower("1 2");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Pair { first, .. } = root.data else {
            panic!("application root has pair payload");
        };
        let first_span = ir.arena.node(first).expect("function exists").span;
        let error = eval_whnf(&ir).expect_err("integer is not callable");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "lambda",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), first_span);

        let manual = manual_ir(
            IrId::new(1),
            vec![
                pure_node(IrKind::Int, first_span, IrData::Int(1)),
                pure_node(
                    IrKind::Apply,
                    Span::new(0, 4),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(99),
                    },
                ),
            ],
        );
        let manual_error =
            eval_whnf(&manual).expect_err("function type wins before lazy argument lookup");

        assert_eq!(
            manual_error.kind(),
            TreeWalkErrorKind::Type {
                id: IrId::new(0),
                expected: "lambda",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(manual_error.span(), first_span);
    }

    #[test]
    fn select_static_keys_force_lazy_values() {
        assert_eq!(eval("({ a = 1 + 2; }).a").as_int(), Ok(3));

        let ir = lower("({ a = 1 / 0; }).a");
        let error = eval_whnf_owned(&ir).expect_err("selected field thunk is forced");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn select_defaults_are_lazy_and_forced_when_missing() {
        assert_eq!(eval("({ a = 1; }).a or (1 / 0)").as_int(), Ok(1));
        assert_eq!(eval("({ a = 1; }).b or (1 + 2)").as_int(), Ok(3));
        assert_eq!(eval("({}).a.b or 2").as_int(), Ok(2));
        assert_eq!(eval("(1).a or 2").as_int(), Ok(2));
        assert_eq!(eval("({ a = 1; }).a.b or 2").as_int(), Ok(2));

        let ir = lower("({ a = 1; }).b or (1 / 0)");
        let error = eval_whnf_owned(&ir).expect_err("missing key forces default thunk");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn missing_static_select_reports_attribute() {
        let ir = lower("({}).a");
        let symbol = symbol_for(&ir, b"a");
        let error = eval_whnf_owned(&ir).expect_err("missing key without default is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingAttribute {
                id: ir.root,
                symbol,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let nested = lower("({ a = {}; }).a.b");
        let nested_symbol = symbol_for(&nested, b"b");
        let nested_error =
            eval_whnf_owned(&nested).expect_err("missing nested key without default is invalid");

        assert_eq!(
            nested_error.kind(),
            TreeWalkErrorKind::MissingAttribute {
                id: nested.root,
                symbol: nested_symbol,
            }
        );
        assert_eq!(
            nested_error.span(),
            nested.arena.node(nested.root).expect("root exists").span
        );
    }

    #[test]
    fn select_requires_attrset_receivers() {
        let ir = lower("(1).a");
        let error = eval_whnf(&ir).expect_err("integer receiver is not an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: ir.root,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let nested = lower("({ a = 1; }).a.b");
        let nested_error =
            eval_whnf_owned(&nested).expect_err("integer intermediate is not an attrset");

        assert_eq!(
            nested_error.kind(),
            TreeWalkErrorKind::Type {
                id: nested.root,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(
            nested_error.span(),
            nested.arena.node(nested.root).expect("root exists").span
        );
    }

    #[test]
    fn select_evaluates_nested_static_and_dynamic_paths() {
        assert_eq!(eval("({ a = { b = 1 + 2; }; }).a.b").as_int(), Ok(3));
        assert_eq!(eval("({ a = 1; }).${\"a\"}").as_int(), Ok(1));
        assert_eq!(
            eval("let name = \"a\"; in { a = { b = 2; }; }.${name}.b").as_int(),
            Ok(2)
        );
        assert_eq!(eval("({}).${\"a\"}.${1 / 0} or 2").as_int(), Ok(2));
        assert_eq!(eval("(1).${\"a\"} or 2").as_int(), Ok(2));

        let error_ir = lower("({ a = 1 / 0; }).a.b or 2");
        let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let null_key = lower("({ a = 1; }).${null} or 2");
        let null_node = null_key
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| node.kind == IrKind::Null)
            .map(|(index, _)| IrId::new(index as u32))
            .expect("null key expression exists");
        let null_error =
            eval_whnf_owned(&null_key).expect_err("select dynamic null key is invalid");

        assert_eq!(
            null_error.kind(),
            TreeWalkErrorKind::Type {
                id: null_node,
                expected: "string",
                actual: ValueTag::Null,
            }
        );
        assert_eq!(
            null_error.span(),
            null_key
                .arena
                .node(null_node)
                .expect("null key expression exists")
                .span
        );
    }

    #[test]
    fn select_evaluates_receiver_and_reached_dynamic_keys_in_order() {
        let ir = lower("(1 / 0).${\"a\"}");
        let error = eval_whnf_owned(&ir).expect_err("receiver errors before dynamic key success");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
        let division = ir
            .arena
            .nodes()
            .iter()
            .find(|node| node.kind == IrKind::BinOp)
            .expect("division node exists");
        assert_eq!(error.span(), division.span);

        let dynamic_error = lower("({}).${1 / 0} or 2");
        let error = eval_whnf_owned(&dynamic_error)
            .expect_err("first dynamic key errors before default fallback");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn has_attr_detects_single_static_keys_without_forcing_values() {
        assert_eq!(eval("({ a = 1; } ? a)").as_bool(), Ok(true));
        assert_eq!(eval("({ a = 1; } ? z)").as_bool(), Ok(false));
        assert_eq!(eval("({ a = 1 / 0; } ? a)").as_bool(), Ok(true));
        assert_eq!(eval("({ a = 1 / 0; } ? z)").as_bool(), Ok(false));
    }

    #[test]
    fn has_attr_returns_false_for_non_attr_path_values() {
        assert_eq!(eval("(1 ? a)").as_bool(), Ok(false));
        assert_eq!(eval("({ a = 1; } ? a.b)").as_bool(), Ok(false));
    }

    #[test]
    fn has_attr_evaluates_nested_static_and_dynamic_paths() {
        assert_eq!(eval("({ a = { b = 1 / 0; }; } ? a.b)").as_bool(), Ok(true));
        assert_eq!(eval("({ a = {}; } ? a.b)").as_bool(), Ok(false));
        assert_eq!(eval("({ a = 1; } ? ${\"a\"})").as_bool(), Ok(true));
        assert_eq!(eval("({} ? ${\"a\"}.${1 / 0})").as_bool(), Ok(false));
        assert_eq!(eval("(1 ? ${\"a\"})").as_bool(), Ok(false));

        let error_ir = lower("({ a = 1 / 0; } ? a.b)");
        let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let null_key = lower("({ a = 1; } ? ${null})");
        let null_node = null_key
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| node.kind == IrKind::Null)
            .map(|(index, _)| IrId::new(index as u32))
            .expect("null key expression exists");
        let null_error =
            eval_whnf_owned(&null_key).expect_err("has-attr dynamic null key is invalid");

        assert_eq!(
            null_error.kind(),
            TreeWalkErrorKind::Type {
                id: null_node,
                expected: "string",
                actual: ValueTag::Null,
            }
        );
        assert_eq!(
            null_error.span(),
            null_key
                .arena
                .node(null_node)
                .expect("null key expression exists")
                .span
        );
    }

    #[test]
    fn has_attr_evaluates_receiver_and_reached_dynamic_keys_in_order() {
        let ir = lower("((1 / 0) ? ${\"a\"})");
        let error = eval_whnf_owned(&ir).expect_err("receiver errors before dynamic key success");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
        let division = ir
            .arena
            .nodes()
            .iter()
            .find(|node| node.kind == IrKind::BinOp)
            .expect("division node exists");
        assert_eq!(error.span(), division.span);

        let dynamic_error = lower("({} ? ${1 / 0})");
        let error = eval_whnf_owned(&dynamic_error)
            .expect_err("first dynamic has-attr key is still evaluated");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
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
    fn attr_update_type_checks_operands_left_to_right() {
        let lhs_ir = lower("1 // (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("update root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let rhs_ir = lower("{} // 1");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("update root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let rhs_error_ir = lower("{} // (1 / 0)");
        let root = rhs_error_ir
            .arena
            .node(rhs_error_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("update root has binary payload");
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
    fn non_owning_eval_rejects_attr_update_heap_values() {
        let ir = lower("{} // {}");
        let error = eval_whnf(&ir).expect_err("attr update value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::Attrs,
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

        let non_empty_list_ir = lower("[ 1 ]");
        let error = eval_whnf(&non_empty_list_ir).expect_err("non-empty list needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: non_empty_list_ir.root,
                tag: ValueTag::List,
            }
        );
        assert_eq!(
            error.span(),
            non_empty_list_ir
                .arena
                .node(non_empty_list_ir.root)
                .expect("root exists")
                .span
        );

        let attrs_ir = lower("{}");
        let error = eval_whnf(&attrs_ir).expect_err("attrset value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: attrs_ir.root,
                tag: ValueTag::Attrs,
            }
        );
        assert_eq!(
            error.span(),
            attrs_ir
                .arena
                .node(attrs_ir.root)
                .expect("root exists")
                .span
        );

        let lambda_ir = lower("x: x");
        let error = eval_whnf(&lambda_ir).expect_err("lambda value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: lambda_ir.root,
                tag: ValueTag::Lambda,
            }
        );
        assert_eq!(
            error.span(),
            lambda_ir
                .arena
                .node(lambda_ir.root)
                .expect("root exists")
                .span
        );
    }

    #[test]
    fn unsupported_nodes_report_kind_and_span() {
        let ir = lower("./foo");
        let error = eval_whnf(&ir).expect_err("path values are not implemented yet");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedNode {
                id: ir.root,
                kind: IrKind::Path,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn unsupported_operators_report_operator_and_span() {
        let lhs = IrId::new(0);
        let rhs = IrId::new(1);
        let root = IrId::new(2);
        let span = Span::new(0, 6);
        let binary = manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(IrKind::Int, Span::new(5, 6), IrData::Int(2)),
                pure_node(
                    IrKind::BinOp,
                    span,
                    IrData::Binary {
                        op: BinOpKind::PipeRight,
                        lhs,
                        rhs,
                    },
                ),
            ],
        );
        let binary_error = eval_whnf(&binary).expect_err("pipe operator is not implemented yet");
        assert_eq!(
            binary_error.kind(),
            TreeWalkErrorKind::UnsupportedBinaryOp {
                id: root,
                op: BinOpKind::PipeRight,
            }
        );
        assert_eq!(binary_error.span(), span);
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
            (IrKind::AttrSet, IrData::None, "attrset payload"),
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
    fn malformed_variable_and_let_payloads_are_reported() {
        let cases = [
            (IrKind::LocalVar, "local payload"),
            (IrKind::UpvalVar, "upvalue payload"),
            (IrKind::Let, "let payload"),
            (IrKind::With, "with pair"),
            (IrKind::WithVar, "with-var payload"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(10 + index as u32, 11 + index as u32);
            let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
            let error = eval_whnf(&ir).expect_err("malformed variable or let is invalid");

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
    fn malformed_function_payloads_are_reported() {
        let cases = [
            (IrKind::Lambda, "lambda payload"),
            (IrKind::Apply, "application pair"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(20 + index as u32, 21 + index as u32);
            let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
            let error = eval_whnf(&ir).expect_err("malformed function node is invalid");

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
    fn invalid_with_chain_metadata_is_reported() {
        let mut symbols = SymbolTable::new();
        let missing = symbols.intern(b"missing").expect("symbol interns");
        let root = IrId::new(0);
        let span = Span::new(0, 7);
        let invalid_chain = manual_ir_with_with_chains(
            root,
            vec![pure_node(
                IrKind::WithVar,
                span,
                IrData::WithVar {
                    symbol: missing,
                    chain: 0,
                },
            )],
            symbols.clone(),
            Vec::new(),
        );
        let error = eval_whnf(&invalid_chain).expect_err("missing with chain is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidWithChain { id: root, chain: 0 }
        );
        assert_eq!(error.span(), span);

        let scope = IrId::new(1);
        let missing_scope = manual_ir_with_with_chains(
            root,
            vec![
                pure_node(
                    IrKind::WithVar,
                    span,
                    IrData::WithVar {
                        symbol: missing,
                        chain: 0,
                    },
                ),
                pure_node(IrKind::AttrSet, Span::new(10, 12), IrData::None),
            ],
            symbols,
            vec![IrWithChain::new(vec![scope].into_boxed_slice())],
        );
        let error = eval_whnf(&missing_scope).expect_err("inactive with scope is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingWithScope { id: root, scope }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_environment_accesses_are_reported() {
        let root = IrId::new(0);
        let span = Span::new(0, 1);
        let local_ir = manual_ir(
            root,
            vec![pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 })],
        );
        let local_error = eval_whnf(&local_ir).expect_err("local needs an environment");

        assert_eq!(
            local_error.kind(),
            TreeWalkErrorKind::MissingEnvironment { id: root }
        );
        assert_eq!(local_error.span(), span);

        let upval_ir = manual_ir(
            root,
            vec![pure_node(
                IrKind::UpvalVar,
                span,
                IrData::Upval { depth: 0, slot: 0 },
            )],
        );
        let upval_error = eval_whnf(&upval_ir).expect_err("upvalue needs an environment");

        assert_eq!(
            upval_error.kind(),
            TreeWalkErrorKind::InvalidUpvalueDepth {
                id: root,
                depth: 0,
                frames: 0,
            }
        );
        assert_eq!(upval_error.span(), span);
    }

    #[test]
    fn invalid_let_frame_metadata_is_reported() {
        let root = IrId::new(0);
        let body = IrId::new(1);
        let span = Span::new(0, 10);
        let missing_frame = manual_ir(
            root,
            vec![
                pure_node(
                    IrKind::Let,
                    span,
                    IrData::Let {
                        bindings: IrBindingSlice::new(0, 0),
                        body,
                        frame: None,
                    },
                ),
                pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
            ],
        );
        let missing_error = eval_whnf(&missing_frame).expect_err("let frame metadata must exist");

        assert_eq!(
            missing_error.kind(),
            TreeWalkErrorKind::MissingFrameMetadata { id: root }
        );
        assert_eq!(missing_error.span(), span);

        let frame = FrameId::new(0);
        let invalid_frame = manual_ir(
            root,
            vec![
                pure_node(
                    IrKind::Let,
                    span,
                    IrData::Let {
                        bindings: IrBindingSlice::new(0, 0),
                        body,
                        frame: Some(frame),
                    },
                ),
                pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
            ],
        );
        let invalid_error = eval_whnf(&invalid_frame).expect_err("frame id must resolve");

        assert_eq!(
            invalid_error.kind(),
            TreeWalkErrorKind::InvalidFrameId {
                id: root,
                frame: frame.as_u32(),
            }
        );
        assert_eq!(invalid_error.span(), span);
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
    fn invalid_has_attr_paths_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(2);
        let span = Span::new(0, 5);
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::HasAttr,
                    span,
                    IrData::HasAttr {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                    },
                ),
            ],
            symbols,
            vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
        );
        let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidAttrPath { id: root, path }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_select_paths_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(2);
        let span = Span::new(0, 5);
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::Select,
                    span,
                    IrData::Select {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                        default: None,
                    },
                ),
            ],
            symbols,
            vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
        );
        let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidAttrPath { id: root, path }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_has_attr_static_symbols_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(0);
        let span = Span::new(0, 5);
        let symbol = Symbol::new(99);
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::HasAttr,
                    span,
                    IrData::HasAttr {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                    },
                ),
            ],
            SymbolTable::new(),
            vec![Box::new([IrAttrPathSegment::Static(symbol)])],
        );
        let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_select_static_symbols_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(0);
        let span = Span::new(0, 5);
        let symbol = Symbol::new(99);
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::Select,
                    span,
                    IrData::Select {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                        default: None,
                    },
                ),
            ],
            SymbolTable::new(),
            vec![Box::new([IrAttrPathSegment::Static(symbol)])],
        );
        let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_attrset_binding_slices_are_reported() {
        let root = IrId::new(0);
        let slice = IrBindingSlice::new(7, 1);
        let span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: slice,
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            )],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset binding slice must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidBindingSlice { id: root, slice }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_attrset_shape_ids_are_reported() {
        let root = IrId::new(0);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape,
                    bindings: IrBindingSlice::new(0, 0),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            )],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset shape must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidShapeId { id: root, shape }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_recursive_attrset_frame_metadata_is_reported() {
        fn recursive_attrset_ir(frame: Option<FrameId>, frames: Vec<FrameInfo>) -> Ir {
            let mut symbols = SymbolTable::new();
            let a = symbols.intern(b"a").expect("symbol interns");
            let value = IrId::new(0);
            let root = IrId::new(1);
            let mut ir = manual_ir_with_attr_tables(
                root,
                vec![
                    pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                    pure_node(
                        IrKind::AttrSet,
                        Span::new(0, 10),
                        IrData::AttrSet {
                            shape: IrShapeId::new(0),
                            bindings: IrBindingSlice::new(0, 1),
                            recursive: true,
                            has_dynamic: false,
                            frame,
                        },
                    ),
                ],
                symbols,
                vec![IrBinding {
                    key: IrAttrPathSegment::Static(a),
                    value,
                }],
                vec![IrShape::new(vec![a].into_boxed_slice())],
            );
            ir.frames = frames.into_boxed_slice();
            ir
        }

        let missing_frame = recursive_attrset_ir(None, Vec::new());
        let missing_error =
            eval_whnf_owned(&missing_frame).expect_err("recursive attrset frame must exist");

        assert_eq!(
            missing_error.kind(),
            TreeWalkErrorKind::MissingFrameMetadata { id: IrId::new(1) }
        );
        assert_eq!(missing_error.span(), Span::new(0, 10));

        let frame = FrameId::new(0);
        let invalid_frame = recursive_attrset_ir(Some(frame), Vec::new());
        let invalid_error = eval_whnf_owned(&invalid_frame).expect_err("frame id must resolve");

        assert_eq!(
            invalid_error.kind(),
            TreeWalkErrorKind::InvalidFrameId {
                id: IrId::new(1),
                frame: frame.as_u32(),
            }
        );
        assert_eq!(invalid_error.span(), Span::new(0, 10));

        let mismatch = recursive_attrset_ir(
            Some(frame),
            vec![FrameInfo {
                slot_count: 2,
                captures: Vec::new().into_boxed_slice(),
                rec: true,
                has_with: false,
            }],
        );
        let mismatch_error =
            eval_whnf_owned(&mismatch).expect_err("frame slots must match bindings");

        assert_eq!(
            mismatch_error.kind(),
            TreeWalkErrorKind::AttrSetFrameSlotMismatch {
                id: IrId::new(1),
                frame_slots: 2,
                bindings: 1,
            }
        );
        assert_eq!(mismatch_error.span(), Span::new(0, 10));
    }

    #[test]
    fn attrset_shape_length_mismatches_are_reported() {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let value = IrId::new(0);
        let root = IrId::new(1);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 8);
        let ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    span,
                    IrData::AttrSet {
                        shape,
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Static(a),
                value,
            }],
            vec![IrShape::new(Vec::new().into_boxed_slice())],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset shape length must match bindings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                id: root,
                shape,
                shape_keys: 0,
                binding_keys: 1,
            }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn attrset_shape_key_mismatches_are_reported() {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("a symbol interns");
        let b = symbols.intern(b"b").expect("b symbol interns");
        let value = IrId::new(0);
        let root = IrId::new(1);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 8);
        let ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    span,
                    IrData::AttrSet {
                        shape,
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Static(a),
                value,
            }],
            vec![IrShape::new(vec![b].into_boxed_slice())],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset shape keys must match bindings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::AttrSetShapeKeyMismatch {
                id: root,
                shape,
                index: 0,
                expected: b,
                actual: a,
            }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn dynamic_attrset_bindings_evaluate_even_with_false_dynamic_flag() {
        let key = IrId::new(0);
        let value = IrId::new(1);
        let root = IrId::new(2);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 12);
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Str, Span::new(3, 8), IrData::Symbol(a)),
                pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    span,
                    IrData::AttrSet {
                        shape,
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Dynamic(key),
                value,
            }],
            vec![IrShape::new(Vec::new().into_boxed_slice())],
        );
        let outcome = eval_whnf_owned(&ir).expect("dynamic key evaluates");
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("attrset is heap-owned");

        assert_eq!(attrs.get(a).expect("dynamic key exists").as_int(), Ok(1));
    }

    #[test]
    fn malformed_thunk_payloads_are_reported_through_list_children() {
        let root = IrId::new(0);
        let child = IrId::new(1);
        let root_span = Span::new(0, 7);
        let child_span = Span::new(2, 5);
        let ir = empty_ir(
            root,
            IrArena::from_raw_parts(
                vec![
                    pure_node(
                        IrKind::List,
                        root_span,
                        IrData::Children(IrChildSlice::new(0, 1)),
                    ),
                    pure_node(IrKind::ThunkAlloc, child_span, IrData::None),
                ],
                vec![child],
            ),
        );

        let error = eval_whnf_owned(&ir).expect_err("malformed thunk child is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: child,
                kind: IrKind::ThunkAlloc,
                expected: "thunk body",
            }
        );
        assert_eq!(error.span(), child_span);
    }

    #[test]
    fn malformed_thunk_body_ids_are_reported_through_list_children() {
        let root = IrId::new(0);
        let child = IrId::new(1);
        let missing = IrId::new(99);
        let root_span = Span::new(0, 7);
        let child_span = Span::new(2, 5);
        let ir = empty_ir(
            root,
            IrArena::from_raw_parts(
                vec![
                    pure_node(
                        IrKind::List,
                        root_span,
                        IrData::Children(IrChildSlice::new(0, 1)),
                    ),
                    pure_node(IrKind::ThunkAlloc, child_span, IrData::Node(missing)),
                ],
                vec![child],
            ),
        );

        let error = eval_whnf_owned(&ir).expect_err("missing thunk body is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidNodeId { id: missing }
        );
        assert_eq!(error.span(), Span::default());
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
    fn integer_add_sub_mul_wrap_on_overflow() {
        let cases = [
            (BinOpKind::Add, i64::MAX, 1, i64::MIN),
            (BinOpKind::Sub, i64::MIN, 1, i64::MAX),
            (BinOpKind::Mul, i64::MAX, 2, -2),
        ];

        for (op, left, right, expected) in cases {
            let value = eval_whnf(&int_binary_ir(op, left, right)).expect("arithmetic evaluates");

            assert_eq!(value.as_int(), Ok(expected));
        }
    }

    #[test]
    fn integer_division_overflow_errors_at_operator_span() {
        let ir = int_binary_ir(BinOpKind::Div, i64::MIN, -1);
        let root_span = ir.arena.node(ir.root).expect("root exists").span;
        let error = eval_whnf(&ir).expect_err("integer division overflows");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ArithmeticOverflow {
                id: ir.root,
                op: ArithmeticOp::Div,
            }
        );
        assert_eq!(error.span(), root_span);
    }

    #[test]
    fn numeric_operators_force_rhs_before_type_checks() {
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
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("subtraction root has binary payload");
        };
        let rhs_span = lhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("rhs evaluation error wins before lhs type");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let lhs_type_ir = lower("true - false");
        let root = lhs_type_ir
            .arena
            .node(lhs_type_ir.root)
            .expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("subtraction root has binary payload");
        };
        let lhs_span = lhs_type_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&lhs_type_ir).expect_err("boolean lhs is invalid after rhs force");

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
                .values_equal(ir.root, &node, left, right, EqualityContext::Direct)
                .expect("strings compare"),
            true
        );
    }

    #[test]
    fn list_equality_is_structural_and_short_circuits() {
        assert_eq!(eval("[1 \"a\" null] == [1 \"a\" null]").as_bool(), Ok(true));
        assert_eq!(eval("[1] != [1 2]").as_bool(), Ok(true));
        assert_eq!(eval("[1 2] == [1 3]").as_bool(), Ok(false));
        assert_eq!(eval("[1 (1 / 0)] == [2 (1 / 0)]").as_bool(), Ok(false));
        assert_eq!(eval("let f = x: x; in [ f ] == [ f ]").as_bool(), Ok(true));
        assert_eq!(eval("[ (x: x) ] == [ (x: x) ]").as_bool(), Ok(false));
        assert_eq!(
            eval("let v = { a = x: x; }; in [ v.a ] == [ v.a ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let v = { a = x: x; }; xs = [ v.a ]; in xs == xs").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let xs = [ (1 / 0) ]; in [ xs ] == [ xs ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in [ nan ] == [ nan ]")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(
                "[ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ] == [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn attrset_equality_is_structural_and_short_circuits() {
        assert_eq!(
            eval("{ b = 2; a = 1; } == { a = 1; b = 2; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("{ a = 1; } == { a = 1; b = 1 / 0; }").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("{ a = 1; z = 1 / 0; } == { a = 2; z = 1 / 0; }").as_bool(),
            Ok(false)
        );
        let z_first = lower("{ z = 1 / 0; a = 1; } == { a = 2; z = 1 / 0; }");
        let z_error = eval_whnf(&z_first).expect_err("symbol-order comparison forces z first");
        let TreeWalkErrorKind::DivisionByZero { .. } = z_error.kind() else {
            panic!("expected division by zero from z value");
        };
        assert_eq!(
            eval("{ a = { x = 1; }; } == { a = { x = 1; }; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = x: x; in { inherit f; } == { inherit f; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let s = { a = 1 / 0; }; in [ s ] == [ s ]").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn direct_function_equality_is_always_false() {
        assert_eq!(eval("let f = x: x; in f == f").as_bool(), Ok(false));
        assert_eq!(eval("let f = x: x; in f != f").as_bool(), Ok(true));
        assert_eq!(
            eval("let f = x: x; g = x: x; in f == g").as_bool(),
            Ok(false)
        );
        assert_eq!(eval("(x: x) == 1").as_bool(), Ok(false));

        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = ir.arena.node(ir.root).expect("root exists");
        let ptr = NonNull::<HeapObject>::dangling();
        let lambda = Value::lambda(ptr).expect("aligned lambda pointer");
        let primop = Value::primop(ptr).expect("aligned primop pointer");
        assert_eq!(
            evaluator.values_equal(ir.root, node, primop, primop, EqualityContext::Direct),
            Ok(false)
        );
        assert_eq!(
            evaluator.values_equal(ir.root, node, lambda, primop, EqualityContext::Direct),
            Ok(false)
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
    fn raw_thunk_equality_is_unsupported() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = ir.arena.node(ir.root).expect("root exists");
        let ptr = NonNull::<HeapObject>::dangling();
        let left = Value::thunk(ptr).expect("aligned thunk pointer");
        let right = Value::thunk(ptr).expect("aligned thunk pointer");

        let error = evaluator
            .values_equal(ir.root, node, left, right, EqualityContext::Direct)
            .expect_err("raw thunk equality is not supported");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedEqualityType {
                id: ir.root,
                left: ValueTag::Thunk,
                right: ValueTag::Thunk,
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
    fn list_comparisons_are_lexicographic() {
        assert_eq!(eval("[1 2] < [1 3]").as_bool(), Ok(true));
        assert_eq!(eval("[1 3] > [1 2]").as_bool(), Ok(true));
        assert_eq!(eval("[1 2] <= [1 2]").as_bool(), Ok(true));
        assert_eq!(eval("[1 2] >= [1 3]").as_bool(), Ok(false));
        assert_eq!(eval("[1] < [1 0]").as_bool(), Ok(true));
        assert_eq!(eval("[1 0] > [1]").as_bool(), Ok(true));
        assert_eq!(eval("[] < [0]").as_bool(), Ok(true));
        assert_eq!(eval("[1 \"a\"] < [1 \"b\"]").as_bool(), Ok(true));
        assert_eq!(eval("[[1 2]] < [[1 3]]").as_bool(), Ok(true));
    }

    #[test]
    fn list_comparisons_short_circuit() {
        assert_eq!(eval("[1 (1 / 0)] < [2 (1 / 0)]").as_bool(), Ok(true));
        assert_eq!(eval("[2 (1 / 0)] < [1 (1 / 0)]").as_bool(), Ok(false));

        let ir = lower("[1 (1 / 0)] <= [1 (2 / 0)]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let left = ir.arena.node(lhs).expect("lhs exists");
        let IrData::Children(left_elements) = left.data else {
            panic!("lhs list has children");
        };
        let left_elements = ir
            .arena
            .child_slice(left_elements)
            .expect("lhs elements exist");
        let throwing_thunk = ir.arena.node(left_elements[1]).expect("thunk exists");
        let IrData::Node(throwing_element) = throwing_thunk.data else {
            panic!("list element is a thunk");
        };
        let throwing_span = ir
            .arena
            .node(throwing_element)
            .expect("throwing element exists")
            .span;

        let error = eval_whnf(&ir).expect_err("equal prefix forces next element");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero {
                id: throwing_element
            }
        );
        assert_eq!(error.span(), throwing_span);
    }

    #[test]
    fn list_comparisons_handle_recursive_container_equality() {
        assert_eq!(eval("let xs = [ xs ]; in xs < xs").as_bool(), Ok(false));
        assert_eq!(eval("let xs = [ xs ]; in xs <= xs").as_bool(), Ok(true));
        assert_eq!(
            eval("let s = rec { a = s; }; in [s] < [s]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let s = rec { a = s; }; in [s] <= [s]").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn structural_equality_still_forces_shared_list_elements() {
        let error = eval_whnf(&lower("let xs = [ (1 / 0) ]; in xs == xs"))
            .expect_err("shared throwing list element is forced");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn list_comparisons_type_check_operands_left_to_right() {
        let rhs_ir = lower("[1] < true");
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
                expected: "list",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let nested_ir = lower("[1] < [\"a\"]");
        let error = eval_whnf_owned(&nested_ir).expect_err("string element is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: nested_ir.root,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(
            error.span(),
            nested_ir
                .arena
                .node(nested_ir.root)
                .expect("root exists")
                .span
        );

        let lhs_ir = lower("false < [(1 / 0)]");
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
                expected: "number, string, or list",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn comparisons_force_operands_before_type_checks() {
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
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = lhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("rhs evaluation error wins before lhs type");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
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
    fn malformed_attr_access_payloads_are_reported() {
        let cases = [
            (IrKind::Select, "select payload"),
            (IrKind::HasAttr, "has-attr payload"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(30 + index as u32, 31 + index as u32);
            let arena = IrArena::from_raw_parts(
                vec![IrNode::new(kind, span, EffectClass::Pure, IrData::None)],
                Vec::new(),
            );
            let ir = empty_ir(root, arena);
            let error = eval_whnf(&ir).expect_err("malformed attr access is invalid");

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
