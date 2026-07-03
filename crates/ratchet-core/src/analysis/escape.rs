//! Escape analysis over lowered IR.
//!
//! This first pass only proves the allocation-free bottom cases: immediate
//! scalar literals that cannot allocate a heap object and therefore cannot
//! publish one outside the current frame. Aggregate values, thunks, strings,
//! paths, variables, primops, and all nodes whose result depends on another
//! expression stay conservative unless the current primitive-operation escape
//! signature table proves an immediate scalar result.

use thiserror::Error;

use crate::analysis::PrimOpEscapeSignature;
use crate::analysis::escape_signature::primop_escape_signature;
use crate::builtins::direct_builtin;
use crate::ir::{Escape, Ir, IrChildSlice, IrData, IrId, IrKind};
use crate::syntax::Symbol;

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
/// immediate scalar literals and direct primops whose escape signatures return
/// an immediate scalar result.
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
    Ok(report)
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

fn validate_payload(id: IrId, node: crate::ir::IrNode) -> Result<(), EscapeAnalysisError> {
    let valid = match node.kind {
        IrKind::Int => matches!(node.data, IrData::Int(_)),
        IrKind::Float => matches!(node.data, IrData::Float(_)),
        IrKind::Bool => matches!(node.data, IrData::Bool(_)),
        IrKind::Null => matches!(node.data, IrData::None),
        IrKind::Str | IrKind::Path | IrKind::Uri | IrKind::GlobalVar | IrKind::BuiltinAttr => {
            matches!(node.data, IrData::Symbol(_))
        }
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

fn primop_signature(
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

fn expected_payload(kind: IrKind) -> &'static str {
    match kind {
        IrKind::Int => "integer payload",
        IrKind::Float => "float payload",
        IrKind::Bool => "boolean payload",
        IrKind::Null => "empty payload",
        IrKind::Str | IrKind::Path | IrKind::Uri => "symbol payload",
        IrKind::LocalVar => "local slot payload",
        IrKind::UpvalVar => "upvalue slot payload",
        IrKind::GlobalVar | IrKind::BuiltinAttr => "symbol payload",
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
