//! Scalar replacement planning over strictness and escape facts.
//!
//! Scalar replacement is a representation optimization: optimized tiers may keep
//! proven-strict, proven-non-escaping values out of the heap. Immediate scalars
//! are admitted directly. Aggregate values are only admitted for the current
//! narrow scratch-allocation case where the aggregate appears exactly once as an
//! argument to an immediate-scalar primitive operation and nowhere else. This
//! module does not rewrite IR. It is a conservative consumer boundary for the
//! current fact table so lowering code can ask which nodes are licensed for
//! non-heap storage without re-deriving every proof predicate.

use thiserror::Error;

use crate::analysis::{PrimOpEscapeSignature, primop_escape_signature};
use crate::builtins::direct_builtin;
use crate::ir::{
    Escape, Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId,
    IrKind, IrShapeId, Strictness,
};
use crate::syntax::Symbol;

/// Builds a scalar replacement plan for the current IR facts.
///
/// Immediate scalar literals and direct primops are admitted only when their
/// facts prove both [`Strictness::DemandedBeforeEffect`] and [`Escape::NoEscape`]. Strict
/// no-escape lists and attrsets are admitted only when the planner can recheck
/// that they are uniquely consumed by an immediate-scalar primop. Scalar
/// candidates with missing proofs are retained with their current facts, while
/// unsupported non-scalar nodes carrying the same proof pair are retained as
/// unsupported by this precursor.
///
/// # Errors
///
/// Returns [`ScalarReplacementError`] if the fact table length does not match
/// the arena node count, if an immediate scalar node carries a payload that does
/// not match its kind, or if a candidate replacement references malformed side
/// tables. Aggregate candidates also recheck uniqueness across the IR, so
/// malformed side tables traversed by that scan, including unrelated child
/// slices, binding keys, or binding values, are rejected before replacement is
/// admitted.
pub fn scalar_replacement_plan(ir: &Ir) -> Result<ScalarReplacementPlan, ScalarReplacementError> {
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(ScalarReplacementError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }
    let mut plan = ScalarReplacementPlan {
        node_count,
        ..ScalarReplacementPlan::default()
    };

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let id = IrId::new(index as u32);
        let facts = ir
            .facts
            .get(id)
            .ok_or(ScalarReplacementError::MissingFact { id })?;

        if let Some(kind) = scalar_kind(ir, id, node.kind, node.data)? {
            plan.scalar_candidate_count += 1;
            if facts.strictness == Strictness::DemandedBeforeEffect
                && facts.escape == Escape::NoEscape
            {
                plan.replacements.push(ScalarReplacement { node: id, kind });
            } else {
                plan.retained.push(ScalarReplacementRetention {
                    node: id,
                    reason: ScalarReplacementRetentionReason::MissingProofs {
                        strictness: facts.strictness,
                        escape: facts.escape,
                    },
                });
            }
            continue;
        }

        if facts.strictness == Strictness::DemandedBeforeEffect && facts.escape == Escape::NoEscape
        {
            match aggregate_kind(ir, id, node.kind, node.data)? {
                Some(kind) => {
                    plan.aggregate_candidate_count += 1;
                    plan.replacements.push(ScalarReplacement { node: id, kind });
                    continue;
                }
                None if matches!(node.kind, IrKind::List | IrKind::AttrSet) => {
                    plan.retained.push(ScalarReplacementRetention {
                        node: id,
                        reason: ScalarReplacementRetentionReason::UnsupportedAggregateConsumer {
                            kind: node.kind,
                        },
                    });
                    continue;
                }
                None => {}
            }
        }

        if facts.strictness == Strictness::DemandedBeforeEffect && facts.escape == Escape::NoEscape
        {
            plan.retained.push(ScalarReplacementRetention {
                node: id,
                reason: ScalarReplacementRetentionReason::UnsupportedNodeKind { kind: node.kind },
            });
        }
    }

    Ok(plan)
}

fn scalar_kind(
    ir: &Ir,
    id: IrId,
    kind: IrKind,
    data: IrData,
) -> Result<Option<ScalarReplacementKind>, ScalarReplacementError> {
    match kind {
        IrKind::Int => match data {
            IrData::Int(_) => Ok(Some(ScalarReplacementKind::Int)),
            _ => Err(invalid_payload(id, kind, "integer payload")),
        },
        IrKind::Float => match data {
            IrData::Float(_) => Ok(Some(ScalarReplacementKind::Float)),
            _ => Err(invalid_payload(id, kind, "float payload")),
        },
        IrKind::Bool => match data {
            IrData::Bool(_) => Ok(Some(ScalarReplacementKind::Bool)),
            _ => Err(invalid_payload(id, kind, "boolean payload")),
        },
        IrKind::Null => match data {
            IrData::None => Ok(Some(ScalarReplacementKind::Null)),
            _ => Err(invalid_payload(id, kind, "empty payload")),
        },
        IrKind::PrimOp => primop_scalar_kind(ir, id, data),
        _ => Ok(None),
    }
}

fn aggregate_kind(
    ir: &Ir,
    id: IrId,
    kind: IrKind,
    data: IrData,
) -> Result<Option<ScalarReplacementKind>, ScalarReplacementError> {
    let replacement = match kind {
        IrKind::List => {
            let IrData::Children(children) = data else {
                return Err(invalid_payload(id, kind, "list child slice"));
            };
            validate_child_slice(ir, id, children)?;
            ScalarReplacementKind::ListAggregate
        }
        IrKind::AttrSet => {
            let IrData::AttrSet {
                shape, bindings, ..
            } = data
            else {
                return Err(invalid_payload(id, kind, "attrset binding payload"));
            };
            validate_shape(ir, id, shape)?;
            validate_binding_slice(ir, id, bindings)?;
            ScalarReplacementKind::AttrSetAggregate
        }
        _ => return Ok(None),
    };
    if unique_scalar_primop_argument(ir, id)? {
        Ok(Some(replacement))
    } else {
        Ok(None)
    }
}

fn unique_scalar_primop_argument(ir: &Ir, argument: IrId) -> Result<bool, ScalarReplacementError> {
    validate_node(ir, ir.root)?;
    let mut reference_count = count_id(ir.root, argument);
    let mut scalar_argument_count = 0usize;

    for with_chain in &ir.with_chains {
        reference_count =
            reference_count.saturating_add(count_validated_ids(ir, &with_chain.scopes, argument)?);
    }

    for (index, node) in ir.arena.nodes().iter().copied().enumerate() {
        let current = IrId::new(index as u32);
        reference_count =
            reference_count.saturating_add(reference_count_in_node(ir, current, node, argument)?);

        let IrData::PrimOp { args, .. } = node.data else {
            continue;
        };
        if primop_scalar_kind(ir, current, node.data)?.is_none() {
            continue;
        }
        scalar_argument_count = scalar_argument_count.saturating_add(count_validated_ids(
            ir,
            child_ids(ir, current, args)?,
            argument,
        )?);
    }

    Ok(reference_count == 1 && scalar_argument_count == 1)
}

fn reference_count_in_node(
    ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
    target: IrId,
) -> Result<usize, ScalarReplacementError> {
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
        IrData::SearchPath { search_path, .. } => {
            count_optional_validated_id(ir, search_path, target)
        }
        IrData::Node(child) => {
            validate_node(ir, child)?;
            Ok(count_id(child, target))
        }
        IrData::Pair { first, second } => {
            validate_node(ir, first)?;
            validate_node(ir, second)?;
            Ok(count_id(first, target) + count_id(second, target))
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            validate_node(ir, first)?;
            validate_node(ir, second)?;
            validate_node(ir, third)?;
            Ok(count_id(first, target) + count_id(second, target) + count_id(third, target))
        }
        IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
            count_validated_ids(ir, child_ids(ir, id, slice)?, target)
        }
        IrData::Bindings(slice) => count_binding_references(ir, id, slice, target),
        IrData::Binary { lhs, rhs, .. } => {
            validate_node(ir, lhs)?;
            validate_node(ir, rhs)?;
            Ok(count_id(lhs, target) + count_id(rhs, target))
        }
        IrData::Unary { operand, .. } => {
            validate_node(ir, operand)?;
            Ok(count_id(operand, target))
        }
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            validate_node(ir, receiver)?;
            if let Some(default) = default {
                validate_node(ir, default)?;
            }
            Ok(count_id(receiver, target)
                + count_optional_id(default, target)
                + count_attr_path_references(ir, id, path, target)?)
        }
        IrData::HasAttr { receiver, path, .. } => {
            validate_node(ir, receiver)?;
            Ok(count_id(receiver, target) + count_attr_path_references(ir, id, path, target)?)
        }
        IrData::DialectNode { argument, .. } => {
            validate_node(ir, argument)?;
            Ok(count_id(argument, target))
        }
        IrData::Lambda { pattern, body, .. } => {
            validate_node(ir, pattern)?;
            validate_node(ir, body)?;
            Ok(count_id(pattern, target) + count_id(body, target))
        }
        IrData::Let { bindings, body, .. } => {
            validate_node(ir, body)?;
            Ok(count_binding_references(ir, id, bindings, target)? + count_id(body, target))
        }
        IrData::AttrSet { bindings, .. } => count_binding_references(ir, id, bindings, target),
        IrData::FormalSet { formals, .. } => {
            count_validated_ids(ir, child_ids(ir, id, formals)?, target)
        }
        IrData::Formal { default, .. } => count_optional_validated_id(ir, default, target),
    }
}

fn count_binding_references(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
    target: IrId,
) -> Result<usize, ScalarReplacementError> {
    let bindings = binding_slice(ir, id, slice)?;

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

fn binding_slice(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
) -> Result<&[crate::ir::IrBinding], ScalarReplacementError> {
    let start = slice.start as usize;
    let end = start
        .checked_add(slice.len())
        .ok_or(ScalarReplacementError::InvalidBindingSlice { id, slice })?;
    ir.bindings
        .get(start..end)
        .ok_or(ScalarReplacementError::InvalidBindingSlice { id, slice })
}

fn count_attr_path_references(
    ir: &Ir,
    id: IrId,
    path: IrAttrPathId,
    target: IrId,
) -> Result<usize, ScalarReplacementError> {
    let segments = ir
        .attr_paths
        .get(path.index())
        .ok_or(ScalarReplacementError::InvalidAttrPath { id, path })?;
    let mut count = 0usize;
    for segment in segments {
        if let IrAttrPathSegment::Dynamic(dynamic) = segment {
            validate_node(ir, *dynamic)?;
            count += count_id(*dynamic, target);
        }
    }
    Ok(count)
}

fn child_ids(ir: &Ir, id: IrId, slice: IrChildSlice) -> Result<&[IrId], ScalarReplacementError> {
    ir.arena
        .child_slice(slice)
        .ok_or(ScalarReplacementError::InvalidChildSlice { id, slice })
}

fn count_validated_ids(
    ir: &Ir,
    ids: &[IrId],
    target: IrId,
) -> Result<usize, ScalarReplacementError> {
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

fn count_optional_validated_id(
    ir: &Ir,
    id: Option<IrId>,
    target: IrId,
) -> Result<usize, ScalarReplacementError> {
    if let Some(id) = id {
        validate_node(ir, id)?;
        Ok(count_id(id, target))
    } else {
        Ok(0)
    }
}

fn count_id(id: IrId, target: IrId) -> usize {
    usize::from(id == target)
}

fn primop_scalar_kind(
    ir: &Ir,
    id: IrId,
    data: IrData,
) -> Result<Option<ScalarReplacementKind>, ScalarReplacementError> {
    let IrData::PrimOp { symbol, args } = data else {
        return match data {
            IrData::DialectNode { .. } | IrData::DialectScopeVar { .. } => Ok(None),
            _ => Err(invalid_payload(id, IrKind::PrimOp, "primop payload")),
        };
    };
    let actual_arity = validate_child_slice(ir, id, args)?;
    let name = ir
        .symbols
        .resolve(symbol)
        .ok_or(ScalarReplacementError::InvalidSymbol { id, symbol })?;
    let Some(direct) = direct_builtin(name) else {
        return Ok(None);
    };
    let expected = direct.arity();
    if actual_arity != expected {
        return Err(ScalarReplacementError::InvalidPrimOpArity {
            id,
            symbol,
            expected,
            actual: actual_arity,
        });
    }
    match primop_escape_signature(name) {
        PrimOpEscapeSignature::ImmediateScalar => {
            Ok(Some(ScalarReplacementKind::PrimOpImmediateScalar))
        }
        PrimOpEscapeSignature::Conservative => Ok(None),
    }
}

fn validate_child_slice(
    ir: &Ir,
    id: IrId,
    slice: IrChildSlice,
) -> Result<usize, ScalarReplacementError> {
    let children = child_ids(ir, id, slice)?;
    for child in children {
        validate_node(ir, *child)?;
    }
    Ok(children.len())
}

fn validate_binding_slice(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
) -> Result<usize, ScalarReplacementError> {
    let bindings = binding_slice(ir, id, slice)?;
    for binding in bindings {
        if let IrAttrPathSegment::Dynamic(key) = binding.key {
            validate_node(ir, key)?;
        }
        validate_node(ir, binding.value)?;
    }
    Ok(bindings.len())
}

fn validate_shape(ir: &Ir, id: IrId, shape: IrShapeId) -> Result<(), ScalarReplacementError> {
    ir.shapes
        .get(shape.index())
        .ok_or(ScalarReplacementError::InvalidShape { id, shape })?;
    Ok(())
}

fn validate_node(ir: &Ir, id: IrId) -> Result<(), ScalarReplacementError> {
    ir.arena
        .node(id)
        .ok_or(ScalarReplacementError::InvalidNode { id })?;
    Ok(())
}

fn invalid_payload(id: IrId, kind: IrKind, expected: &'static str) -> ScalarReplacementError {
    ScalarReplacementError::InvalidPayload { id, kind, expected }
}

/// A conservative scalar replacement plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScalarReplacementPlan {
    node_count: usize,
    scalar_candidate_count: usize,
    aggregate_candidate_count: usize,
    replacements: Vec<ScalarReplacement>,
    retained: Vec<ScalarReplacementRetention>,
}

impl ScalarReplacementPlan {
    /// Returns the number of IR nodes scanned.
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns the number of immediate scalar candidates considered.
    pub const fn scalar_candidate_count(&self) -> usize {
        self.scalar_candidate_count
    }

    /// Returns the number of aggregate scratch candidates admitted.
    pub const fn aggregate_candidate_count(&self) -> usize {
        self.aggregate_candidate_count
    }

    /// Returns nodes licensed for non-heap representation.
    pub fn replacements(&self) -> &[ScalarReplacement] {
        &self.replacements
    }

    /// Returns nodes retained with the reason scalar replacement was withheld.
    pub fn retained(&self) -> &[ScalarReplacementRetention] {
        &self.retained
    }

    /// Returns whether no node can be replaced.
    pub fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }
}

/// One IR node licensed for non-heap representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarReplacement {
    node: IrId,
    kind: ScalarReplacementKind,
}

impl ScalarReplacement {
    /// Returns the IR node covered by this replacement proof.
    pub const fn node(self) -> IrId {
        self.node
    }

    /// Returns the non-heap representation class.
    pub const fn kind(self) -> ScalarReplacementKind {
        self.kind
    }
}

/// Non-heap representation classes supported by this planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarReplacementKind {
    /// An integer scalar.
    Int,
    /// A floating-point scalar.
    Float,
    /// A boolean scalar.
    Bool,
    /// The null singleton.
    Null,
    /// A direct primitive operation whose result is an immediate scalar.
    PrimOpImmediateScalar,
    /// A list allocation uniquely consumed by an immediate-scalar primop.
    ListAggregate,
    /// An attrset allocation uniquely consumed by an immediate-scalar primop.
    AttrSetAggregate,
}

/// One node retained by the scalar replacement planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarReplacementRetention {
    node: IrId,
    reason: ScalarReplacementRetentionReason,
}

impl ScalarReplacementRetention {
    /// Returns the retained IR node.
    pub const fn node(self) -> IrId {
        self.node
    }

    /// Returns why scalar replacement was not licensed.
    pub const fn reason(self) -> ScalarReplacementRetentionReason {
        self.reason
    }
}

/// Why scalar replacement was withheld for a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarReplacementRetentionReason {
    /// The scalar node did not have both required facts.
    MissingProofs {
        /// The strictness fact that prevented replacement.
        strictness: Strictness,
        /// The escape fact that prevented replacement.
        escape: Escape,
    },
    /// The node is not a replacement kind supported by this precursor.
    UnsupportedNodeKind {
        /// The unsupported node kind.
        kind: IrKind,
    },
    /// The aggregate proof did not have the required scalar-primop consumer.
    UnsupportedAggregateConsumer {
        /// The aggregate node kind that was retained.
        kind: IrKind,
    },
}

/// A failure while building a scalar replacement plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ScalarReplacementError {
    /// A fact record was missing for an arena node.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The node whose fact record was missing.
        id: IrId,
    },
    /// A scalar node's payload did not match its node kind.
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
    /// An attribute-set shape id did not resolve through the shape table.
    #[error("invalid attribute-set shape {shape:?} at IR node {id:?}")]
    InvalidShape {
        /// The node that referenced the invalid shape.
        id: IrId,
        /// The invalid shape id.
        shape: IrShapeId,
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
