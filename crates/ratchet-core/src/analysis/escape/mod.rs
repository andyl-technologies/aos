//! Escape analysis over lowered IR.
//!
//! The pass proves the allocation-free bottom cases — immediate scalar
//! literals, scalar-result primitive operations (via the escape-signature
//! table), strict aggregates uniquely consumed by such operations, and strict
//! thunk wrappers around already-proven bodies — plus, in the
//! [`mod@frame_local`] submodule, a per-frame reachability proof for lazy
//! `let` binding thunks: a binding thunk is frame-local when every reference
//! to its slot across the frame sits in a consuming position (the S9
//! result/primop clauses) and no reference is reachable from a closure
//! capture, a container, an unknown call argument, or an interning boundary.

use thiserror::Error;

use crate::analysis::PrimOpEscapeSignature;
use crate::analysis::escape_signature::primop_escape_signature;
use crate::builtins::direct_builtin;
use crate::ir::{
    Escape, Ir, IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData,
    IrId, IrKind,
};
use crate::syntax::Symbol;

mod frame_local;

/// Summary of one escape annotation run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EscapeAnalysisReport {
    /// Number of fact records changed to no-escape.
    pub nodes_marked_no_escape: usize,
    /// Number of fact records reset to escaping.
    pub nodes_reset_to_escaping: usize,
}

/// Errors returned when escape analysis sees malformed IR storage.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EscapeAnalysisError {
    /// A fact record was missing for an arena node.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The node whose fact record was missing.
        id: IrId,
    },
    /// A node's payload did not match its node kind.
    #[error("invalid payload for {kind:?} node {id:?}: expected {expected}")]
    InvalidPayload {
        /// The node with the invalid payload.
        id: IrId,
        /// The node kind whose payload was invalid.
        kind: IrKind,
        /// The expected payload shape.
        expected: &'static str,
    },
    /// A child slice did not resolve through the child pool.
    #[error("invalid child slice {slice:?} at IR node {id:?}")]
    InvalidChildSlice {
        /// The node that referenced the invalid child slice.
        id: IrId,
        /// The invalid child slice.
        slice: IrChildSlice,
    },
    /// A binding slice did not resolve through the binding table.
    #[error("invalid binding slice {slice:?} at IR node {id:?}")]
    InvalidBindingSlice {
        /// The node that referenced the invalid binding slice.
        id: IrId,
        /// The invalid binding slice.
        slice: IrBindingSlice,
    },
    /// An attribute path id did not resolve through the attribute-path table.
    #[error("invalid attribute path {path:?} at IR node {id:?}")]
    InvalidAttrPath {
        /// The node that referenced the invalid path.
        id: IrId,
        /// The invalid path id.
        path: IrAttrPathId,
    },
    /// A child id did not resolve through the arena.
    #[error("invalid IR node id {id:?}")]
    InvalidNode {
        /// The invalid child node id.
        id: IrId,
    },
    /// A primop symbol did not resolve through the symbol table.
    #[error("invalid primop symbol {symbol:?} at IR node {id:?}")]
    InvalidSymbol {
        /// The primop node.
        id: IrId,
        /// The unresolved symbol.
        symbol: Symbol,
    },
    /// A direct primop node carried the wrong number of arguments.
    #[error(
        "invalid direct primop arity for symbol {symbol:?} at IR node {id:?}: expected {expected}, got {actual}"
    )]
    InvalidPrimOpArity {
        /// The primop node.
        id: IrId,
        /// The direct primop symbol.
        symbol: Symbol,
        /// The expected direct-primop argument count.
        expected: usize,
        /// The actual lowered argument count.
        actual: usize,
    },
    /// The fact table length did not match the arena node count.
    #[error("invalid fact table length: expected {expected}, got {actual}")]
    InvalidFactTableLength {
        /// The number of fact records required by the arena.
        expected: usize,
        /// The number of fact records present.
        actual: usize,
    },
}

/// Annotates nodes whose result is proven not to publish an allocation.
///
/// The pass owns the current escape fact approximation. It resets every visited
/// node to [`Escape::Escapes`] unless this pass positively proves
/// [`Escape::NoEscape`]. The current positive proofs are allocation-free
/// immediate scalar literals, direct primops whose escape signatures return an
/// immediate scalar result, strict aggregate allocations uniquely consumed by
/// such scalar-result primops, strict thunk allocations that are the unique
/// argument reference to a direct simple identity lambda whose body result is
/// already proven not to escape, and lazy `let` binding thunks admitted by the
/// per-frame reachability proof in [`mod@frame_local`] (every slot reference
/// sits in a consuming or result-flow position; captures, containers, unknown
/// call arguments, and interning boundaries decline).
///
/// # Errors
///
/// Returns [`EscapeAnalysisError`] if the fact table is missing an arena entry,
/// if a node payload does not match its kind, or if a primop references
/// malformed side-table entries.
pub fn annotate_escape(ir: &mut Ir) -> Result<EscapeAnalysisReport, EscapeAnalysisError> {
    let mut report = EscapeAnalysisReport::default();
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(EscapeAnalysisError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }
    for index in 0..ir.facts.len() {
        let id = IrId::new(index as u32);
        let facts = ir
            .facts
            .get_mut(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        if facts.escape == Escape::NoEscape {
            facts.escape = Escape::Escapes;
            report.nodes_reset_to_escaping += 1;
        }
    }

    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        validate_payload(id, node)?;
        ir.facts
            .get(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
    }

    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        if !is_allocation_free_scalar(node) {
            continue;
        }
        let facts = ir
            .facts
            .get_mut(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        facts.escape = Escape::NoEscape;
        report.nodes_marked_no_escape += 1;
    }
    for thunk in frame_local::frame_local_let_thunks(ir)? {
        let facts = ir
            .facts
            .get_mut(thunk)
            .ok_or(EscapeAnalysisError::MissingFact { id: thunk })?;
        facts.escape = Escape::NoEscape;
        report.nodes_marked_no_escape += 1;
    }
    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        let Some(signature) = primop_signature(ir, id, node.data)? else {
            continue;
        };
        if signature.escape() != Escape::NoEscape {
            continue;
        }
        let facts = ir
            .facts
            .get_mut(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        facts.escape = Escape::NoEscape;
        report.nodes_marked_no_escape += 1;
    }
    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        if !strict_thunk_wraps_no_escape_body(ir, id, node)? {
            continue;
        }
        let facts = ir
            .facts
            .get_mut(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        facts.escape = Escape::NoEscape;
        report.nodes_marked_no_escape += 1;
    }
    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        if !strict_aggregate_consumed_by_scalar_primop(ir, id, node)? {
            continue;
        }
        let facts = ir
            .facts
            .get_mut(id)
            .ok_or(EscapeAnalysisError::MissingFact { id })?;
        facts.escape = Escape::NoEscape;
        report.nodes_marked_no_escape += 1;
    }
    annotate_lambda_call_summary_escape(ir)?;
    Ok(report)
}

/// Refines only the escape fields carried by persisted lambda call summaries.
///
/// This narrow producer supports fresh imported modules, which need their
/// cross-module contracts immediately but do not otherwise consume per-node
/// escape facts before a durable full-analysis refresh.
///
/// # Errors
///
/// Returns [`EscapeAnalysisError`] when a summarized lambda frame or any node
/// reachable by its escape scan is malformed.
pub fn annotate_lambda_call_summary_escape(ir: &mut Ir) -> Result<(), EscapeAnalysisError> {
    let lambda_escapes = frame_local::lambda_frame_escapes(ir)?;
    for lambda in lambda_escapes {
        let Some(summary) = ir
            .facts
            .lambda_call_summaries_mut()
            .iter_mut()
            .find(|summary| summary.pattern == lambda.pattern)
        else {
            continue;
        };
        summary.argument_escape = lambda.argument;
        for (formal, escape) in summary.formals.iter_mut().zip(lambda.slots) {
            formal.escape = escape;
        }
    }
    Ok(())
}

pub(super) fn binding_values(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
) -> Result<&[IrBinding], EscapeAnalysisError> {
    let start = slice.start as usize;
    let end = start
        .checked_add(slice.len())
        .ok_or(EscapeAnalysisError::InvalidBindingSlice { id, slice })?;
    ir.bindings
        .get(start..end)
        .ok_or(EscapeAnalysisError::InvalidBindingSlice { id, slice })
}

fn is_allocation_free_scalar(node: crate::ir::IrNode) -> bool {
    matches!(
        (node.kind, node.data),
        (IrKind::Int, IrData::Int(_))
            | (IrKind::Float, IrData::Float(_))
            | (IrKind::Bool, IrData::Bool(_))
            | (IrKind::Null, IrData::None)
    )
}

pub(super) fn validate_payload(
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<(), EscapeAnalysisError> {
    let valid = match node.kind {
        IrKind::Int => matches!(node.data, IrData::Int(_)),
        IrKind::Float => matches!(node.data, IrData::Float(_)),
        IrKind::Bool => matches!(node.data, IrData::Bool(_)),
        IrKind::Null => matches!(node.data, IrData::None),
        IrKind::Str | IrKind::Path | IrKind::Uri | IrKind::BuiltinAttr => {
            matches!(node.data, IrData::Symbol(_))
        }
        IrKind::GlobalVar => matches!(node.data, IrData::GlobalVar { .. }),
        IrKind::LocalVar => matches!(node.data, IrData::Local { .. }),
        IrKind::UpvalVar => matches!(node.data, IrData::Upval { .. }),
        IrKind::SearchPath => matches!(node.data, IrData::SearchPath { .. }),
        IrKind::List => matches!(node.data, IrData::Children(_)),
        IrKind::AttrSet => matches!(node.data, IrData::AttrSet { .. }),
        IrKind::Lambda => matches!(node.data, IrData::Lambda { .. }),
        IrKind::FormalSet => matches!(node.data, IrData::FormalSet { .. }),
        IrKind::Formal => matches!(node.data, IrData::Formal { .. }),
        IrKind::Apply | IrKind::With | IrKind::Assert => matches!(node.data, IrData::Pair { .. }),
        IrKind::Select => matches!(node.data, IrData::Select { .. }),
        IrKind::HasAttr => matches!(node.data, IrData::HasAttr { .. }),
        IrKind::Let => matches!(node.data, IrData::Let { .. }),
        IrKind::If => matches!(node.data, IrData::Triple { .. }),
        IrKind::BinOp => matches!(node.data, IrData::Binary { .. }),
        IrKind::UnaryOp => matches!(node.data, IrData::Unary { .. }),
        IrKind::Interp => matches!(
            node.data,
            IrData::Node(_) | IrData::Children(_) | IrData::None
        ),
        IrKind::ThunkAlloc => matches!(node.data, IrData::Node(_)),
        IrKind::PrimOp => matches!(
            node.data,
            IrData::PrimOp { .. } | IrData::DialectNode { .. } | IrData::DialectScopeVar { .. }
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(EscapeAnalysisError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        })
    }
}

fn strict_thunk_wraps_no_escape_body(
    ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<bool, EscapeAnalysisError> {
    let IrKind::ThunkAlloc = node.kind else {
        return Ok(false);
    };
    let IrData::Node(body) = node.data else {
        return Err(EscapeAnalysisError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        });
    };
    ir.arena
        .node(body)
        .ok_or(EscapeAnalysisError::InvalidNode { id: body })?;

    let facts = ir
        .facts
        .get(id)
        .ok_or(EscapeAnalysisError::MissingFact { id })?;
    let body_facts = ir
        .facts
        .get(body)
        .ok_or(EscapeAnalysisError::MissingFact { id: body })?;

    if !facts.strictness.is_demanded() || body_facts.escape != Escape::NoEscape {
        return Ok(false);
    }

    unique_direct_identity_lambda_argument(ir, id)
}

fn unique_direct_identity_lambda_argument(
    ir: &Ir,
    argument: IrId,
) -> Result<bool, EscapeAnalysisError> {
    let reference_count = direct_reference_count(ir, argument)?;
    let mut identity_argument_count = 0usize;

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let current = IrId::new(index as u32);
        if node.kind != IrKind::Apply {
            continue;
        }
        let IrData::Pair {
            first: callee,
            second,
        } = node.data
        else {
            return Err(EscapeAnalysisError::InvalidPayload {
                id: current,
                kind: node.kind,
                expected: expected_payload(node.kind),
            });
        };
        if second != argument {
            continue;
        }
        let callee_node = *ir
            .arena
            .node(callee)
            .ok_or(EscapeAnalysisError::InvalidNode { id: callee })?;
        if callee_node.kind != IrKind::Lambda {
            return Ok(false);
        }
        if simple_identity_lambda(ir, callee, callee_node)? {
            identity_argument_count = identity_argument_count.saturating_add(1);
        }
    }

    Ok(reference_count == 1 && identity_argument_count == 1)
}

pub(super) fn direct_reference_count(ir: &Ir, target: IrId) -> Result<usize, EscapeAnalysisError> {
    let mut reference_count = count_id(ir.root, target);

    for with_chain in &ir.with_chains {
        reference_count =
            reference_count.saturating_add(count_validated_ids(ir, &with_chain.scopes, target)?);
    }

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let current = IrId::new(index as u32);
        reference_count =
            reference_count.saturating_add(reference_count_in_node(ir, current, node, target)?);
    }

    Ok(reference_count)
}

fn simple_identity_lambda(
    ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<bool, EscapeAnalysisError> {
    let IrData::Lambda { pattern, body, .. } = node.data else {
        return Err(EscapeAnalysisError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        });
    };
    let pattern_node = *ir
        .arena
        .node(pattern)
        .ok_or(EscapeAnalysisError::InvalidNode { id: pattern })?;
    let body_node = *ir
        .arena
        .node(body)
        .ok_or(EscapeAnalysisError::InvalidNode { id: body })?;

    let simple_pattern = matches!(
        (pattern_node.kind, pattern_node.data),
        (IrKind::Formal, IrData::Formal { default: None, .. })
    );
    let identity_body = matches!(
        (body_node.kind, body_node.data),
        (IrKind::LocalVar, IrData::Local { slot: 0 })
    );
    Ok(simple_pattern && identity_body)
}

fn reference_count_in_node(
    ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
    target: IrId,
) -> Result<usize, EscapeAnalysisError> {
    match node.data {
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::GlobalVar { .. }
        | IrData::Local { .. }
        | IrData::Upval { .. }
        | IrData::DialectScopeVar { .. } => Ok(0),
        IrData::SearchPath { search_path, .. } => Ok(count_optional_id(search_path, target)),
        IrData::Node(child) => Ok(count_id(child, target)),
        IrData::Pair { first, second } => Ok(count_id(first, target) + count_id(second, target)),
        IrData::Triple {
            first,
            second,
            third,
        } => Ok(count_id(first, target) + count_id(second, target) + count_id(third, target)),
        IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
            Ok(count_ids(child_ids(ir, id, slice)?, target))
        }
        IrData::Bindings(slice) => count_binding_references(ir, id, slice, target),
        IrData::Binary { lhs, rhs, .. } => Ok(count_id(lhs, target) + count_id(rhs, target)),
        IrData::Unary { operand, .. } => Ok(count_id(operand, target)),
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => Ok(count_id(receiver, target)
            + count_optional_id(default, target)
            + count_attr_path_references(ir, id, path, target)?),
        IrData::HasAttr { receiver, path, .. } => {
            Ok(count_id(receiver, target) + count_attr_path_references(ir, id, path, target)?)
        }
        IrData::DialectNode { argument, .. } => Ok(count_id(argument, target)),
        IrData::Lambda { pattern, body, .. } => {
            Ok(count_id(pattern, target) + count_id(body, target))
        }
        IrData::Let { bindings, body, .. } => {
            Ok(count_binding_references(ir, id, bindings, target)? + count_id(body, target))
        }
        IrData::AttrSet { bindings, .. } => count_binding_references(ir, id, bindings, target),
        IrData::FormalSet { formals, .. } => Ok(count_ids(child_ids(ir, id, formals)?, target)),
        IrData::Formal { default, .. } => Ok(count_optional_id(default, target)),
    }
}

fn count_binding_references(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
    target: IrId,
) -> Result<usize, EscapeAnalysisError> {
    let start = slice.start as usize;
    let end = start
        .checked_add(slice.len())
        .ok_or(EscapeAnalysisError::InvalidBindingSlice { id, slice })?;
    let bindings = ir
        .bindings
        .get(start..end)
        .ok_or(EscapeAnalysisError::InvalidBindingSlice { id, slice })?;

    let mut count = 0usize;
    for binding in bindings {
        if let IrAttrPathSegment::Dynamic(key) = binding.key {
            validate_node(ir, key)?;
            count += count_id(key, target);
        }
        validate_node(ir, binding.value)?;
        count += count_id(binding.value, target);
    }
    Ok(count)
}

fn count_attr_path_references(
    ir: &Ir,
    id: IrId,
    path: IrAttrPathId,
    target: IrId,
) -> Result<usize, EscapeAnalysisError> {
    let segments = ir
        .attr_paths
        .get(path.index())
        .ok_or(EscapeAnalysisError::InvalidAttrPath { id, path })?;
    let mut count = 0usize;
    for segment in segments {
        if let IrAttrPathSegment::Dynamic(dynamic) = segment {
            validate_node(ir, *dynamic)?;
            count += count_id(*dynamic, target);
        }
    }
    Ok(count)
}

pub(super) fn child_ids(
    ir: &Ir,
    id: IrId,
    slice: IrChildSlice,
) -> Result<&[IrId], EscapeAnalysisError> {
    ir.arena
        .child_slice(slice)
        .ok_or(EscapeAnalysisError::InvalidChildSlice { id, slice })
}

pub(super) fn validate_node(ir: &Ir, id: IrId) -> Result<(), EscapeAnalysisError> {
    ir.arena
        .node(id)
        .ok_or(EscapeAnalysisError::InvalidNode { id })?;
    Ok(())
}

fn count_ids(ids: &[IrId], target: IrId) -> usize {
    ids.iter().filter(|id| **id == target).count()
}

fn count_validated_ids(ir: &Ir, ids: &[IrId], target: IrId) -> Result<usize, EscapeAnalysisError> {
    let mut count = 0usize;
    for id in ids {
        validate_node(ir, *id)?;
        count += count_id(*id, target);
    }
    Ok(count)
}

fn count_optional_id(id: Option<IrId>, target: IrId) -> usize {
    id.map_or(0, |id| count_id(id, target))
}

fn count_id(id: IrId, target: IrId) -> usize {
    usize::from(id == target)
}

fn strict_aggregate_consumed_by_scalar_primop(
    ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<bool, EscapeAnalysisError> {
    if !matches!(node.kind, IrKind::List | IrKind::AttrSet) {
        return Ok(false);
    }
    let facts = ir
        .facts
        .get(id)
        .ok_or(EscapeAnalysisError::MissingFact { id })?;
    if !facts.strictness.is_demanded() {
        return Ok(false);
    }
    unique_scalar_primop_argument(ir, id)
}

fn unique_scalar_primop_argument(ir: &Ir, argument: IrId) -> Result<bool, EscapeAnalysisError> {
    let reference_count = direct_reference_count(ir, argument)?;
    let mut scalar_argument_count = 0usize;

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let current = IrId::new(index as u32);
        let IrData::PrimOp { args, .. } = node.data else {
            continue;
        };
        let Some(signature) = primop_signature(ir, current, node.data)? else {
            continue;
        };
        if signature.escape() != Escape::NoEscape {
            continue;
        }
        scalar_argument_count = scalar_argument_count
            .saturating_add(count_ids(child_ids(ir, current, args)?, argument));
    }

    Ok(reference_count == 1 && scalar_argument_count == 1)
}

pub(super) fn primop_signature(
    ir: &Ir,
    id: IrId,
    data: IrData,
) -> Result<Option<PrimOpEscapeSignature>, EscapeAnalysisError> {
    let IrData::PrimOp { symbol, args } = data else {
        return Ok(None);
    };
    let actual_arity = validate_child_slice(ir, id, args)?;
    let name = ir
        .symbols
        .resolve(symbol)
        .ok_or(EscapeAnalysisError::InvalidSymbol { id, symbol })?;
    if let Some(direct) = direct_builtin(name) {
        let expected = direct.arity();
        if actual_arity != expected {
            return Err(EscapeAnalysisError::InvalidPrimOpArity {
                id,
                symbol,
                expected,
                actual: actual_arity,
            });
        }
    }
    Ok(Some(primop_escape_signature(name)))
}

fn validate_child_slice(
    ir: &Ir,
    id: IrId,
    slice: IrChildSlice,
) -> Result<usize, EscapeAnalysisError> {
    let children = ir
        .arena
        .child_slice(slice)
        .ok_or(EscapeAnalysisError::InvalidChildSlice { id, slice })?;
    for child in children {
        ir.arena
            .node(*child)
            .ok_or(EscapeAnalysisError::InvalidNode { id: *child })?;
    }
    Ok(children.len())
}

pub(super) fn expected_payload(kind: IrKind) -> &'static str {
    match kind {
        IrKind::Int => "integer payload",
        IrKind::Float => "float payload",
        IrKind::Bool => "boolean payload",
        IrKind::Null => "empty payload",
        IrKind::Str | IrKind::Path | IrKind::Uri => "symbol payload",
        IrKind::LocalVar => "local slot payload",
        IrKind::UpvalVar => "upvalue slot payload",
        IrKind::GlobalVar => "global-var payload",
        IrKind::BuiltinAttr => "symbol payload",
        IrKind::SearchPath => "search-path payload",
        IrKind::List => "children payload",
        IrKind::AttrSet => "attrset payload",
        IrKind::Lambda => "lambda payload",
        IrKind::FormalSet => "formal-set payload",
        IrKind::Formal => "formal payload",
        IrKind::Apply | IrKind::With | IrKind::Assert => "pair payload",
        IrKind::Select => "select payload",
        IrKind::HasAttr => "hasAttr payload",
        IrKind::Let => "let payload",
        IrKind::If => "triple payload",
        IrKind::BinOp => "binary payload",
        IrKind::UnaryOp => "unary payload",
        IrKind::Interp => "interpolation payload",
        IrKind::ThunkAlloc => "thunk body",
        IrKind::PrimOp => "primop payload",
    }
}
