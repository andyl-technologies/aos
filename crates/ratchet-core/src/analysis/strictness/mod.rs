//! Strictness and demand analysis over lowered IR.
//!
//! This pass computes per-node demand facts with *per-execution* semantics:
//! a fact on a node is a claim that holds whenever that node is evaluated by
//! its (unique) syntactic parent, conditional on that evaluation happening.
//!
//! - [`Strictness::DemandedBeforeEffect`] — whenever the node is evaluated,
//!   its value reaches WHNF before any observable event (throw, abort, failed
//!   assert, trace output, divergence) can occur. This is the S1+S2 proof
//!   that licenses eager thunk elision.
//! - [`Strictness::Demanded`] — whenever the node is evaluated, its value
//!   reaches WHNF on every normally-completing continuation, but possibly
//!   only after another observable event. This is the S1-only proof consumed
//!   as a fan-out hint; it never licenses eagerness.
//!
//! The analysis runs in two passes over the (validated, tree-shaped) IR:
//!
//! 1. [`totality`] computes a bottom-up per-node totality bit: whether
//!    evaluating the node in a demand position (including forcing its result
//!    to WHNF) is structurally incapable of throwing, diverging, or emitting
//!    trace output. Totality is what upgrades deferred demand to
//!    `DemandedBeforeEffect` along a path (S2).
//! 2. [`walk`] assigns per-node facts top-down. Positions the evaluator
//!    forces immediately are `DemandedBeforeEffect` outright (eliding a
//!    thunk that is allocated and forced in the same instant is a semantic
//!    no-op). Deferred positions — apply arguments, `let` bindings, selected
//!    attribute values — receive levels computed from per-lambda demand
//!    summaries ([`collect`]), static slot resolution over the scope-resolved
//!    frame stack, and the per-builtin [`crate::builtins::DemandSignature`].
//!
//! `tryEval` is strict in its argument, but demand never propagates through
//! a `tryEval` application into an enclosing lambda's parameter summary
//! (soundness rule S4): a force hoisted above the call would escape the
//! catch. The argument subtree root is additionally flagged with a persisted
//! barrier bit for future relocation passes.
//!
//! Absent or failed proofs always degrade to conservative facts: analysis
//! errors leave the fact table untouched, and IR whose child edges do not
//! form a tree is declined (no facts are produced) rather than analyzed
//! unsoundly.

mod collect;
mod frames;
mod totality;
mod walk;

use std::collections::HashMap;
use std::rc::Rc;

use thiserror::Error;

use crate::ir::{
    Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId, IrKind,
    Strictness,
};
use crate::syntax::Symbol;

use collect::{CollectCtx, SlotDemand};

/// Summary of one strictness annotation run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrictnessAnalysisReport {
    /// Number of fact records strengthened from a weaker demand level.
    pub nodes_marked_strict: usize,
}

/// Errors returned when strictness analysis sees malformed IR storage.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StrictnessAnalysisError {
    /// A node id did not exist in the arena.
    #[error("invalid IR node id {id:?}")]
    InvalidNode {
        /// The invalid node id.
        id: IrId,
    },
    /// The fact table did not contain an entry for an arena node.
    #[error("missing fact record for IR node {id:?}")]
    MissingFact {
        /// The node whose fact record was missing.
        id: IrId,
    },
    /// A child slice did not resolve through the child pool.
    #[error("invalid child slice {slice:?} at IR node {id:?}")]
    InvalidChildSlice {
        /// The node that referenced the invalid child slice.
        id: IrId,
        /// The invalid child slice.
        slice: IrChildSlice,
    },
    /// A frame id did not resolve through the frame table.
    #[error("invalid frame {frame:?} at IR node {id:?}")]
    InvalidFrame {
        /// The node that referenced the invalid frame.
        id: IrId,
        /// The invalid frame id.
        frame: crate::FrameId,
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
    /// A primop symbol did not resolve through the symbol table.
    #[error("invalid primop symbol {symbol:?} at IR node {id:?}")]
    InvalidSymbol {
        /// The primop node.
        id: IrId,
        /// The unresolved symbol.
        symbol: Symbol,
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

/// Annotates IR nodes with positively-proven demand facts.
///
/// The pass mutates `ir.facts` in place. Facts are only strengthened, never
/// weakened, and every error path leaves the fact table exactly as it was.
/// IR whose child edges are shared between parents (non-tree IR) is declined:
/// the call succeeds with no facts marked, because per-execution demand
/// claims require each node to have a single evaluation context.
///
/// # Errors
///
/// Returns [`StrictnessAnalysisError`] if an arena node payload does not match
/// its kind, or if the IR arena, child pool, frame table, binding table,
/// attribute-path table, symbol table, or fact table is internally
/// inconsistent.
pub fn annotate_strictness(
    ir: &mut Ir,
) -> Result<StrictnessAnalysisReport, StrictnessAnalysisError> {
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(StrictnessAnalysisError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }
    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(StrictnessAnalysisError::InvalidNode { id })?;
        validate_payload(id, node)?;
        ir.facts
            .get(id)
            .ok_or(StrictnessAnalysisError::MissingFact { id })?;
    }
    if !edges_form_tree(ir)? {
        return Ok(StrictnessAnalysisReport::default());
    }

    let mut analysis = Analysis::new(ir);
    totality::compute(&mut analysis, ir.root, &mut Vec::new())?;
    walk::run(&mut analysis)?;
    let Analysis {
        marks, barriers, ..
    } = analysis;

    let mut report = StrictnessAnalysisReport::default();
    for (id, level) in marks {
        let facts = ir
            .facts
            .get_mut(id)
            .ok_or(StrictnessAnalysisError::MissingFact { id })?;
        if level > facts.strictness {
            facts.strictness = level;
            report.nodes_marked_strict += 1;
        }
    }
    for id in barriers {
        ir.facts.set_try_eval_barrier(id, true);
    }
    Ok(report)
}

/// Shared state for one strictness analysis run.
///
/// Facts are accumulated in [`Self::marks`] and applied only after both
/// passes complete, so a failing pass cannot leave a partially-refined table.
struct Analysis<'a> {
    ir: &'a Ir,
    /// Per-node totality bits filled by pass 1 (`None` until computed).
    totality: Vec<Option<bool>>,
    /// Memoized demand collections keyed by node and transparency context.
    collect_memo: HashMap<(IrId, CollectCtx), Rc<SlotDemand>>,
    /// Collection cycle guard (uncached in-progress nodes).
    collect_active: Vec<(IrId, CollectCtx)>,
    /// Demand marks to apply after the run completes.
    marks: Vec<(IrId, Strictness)>,
    /// `tryEval` argument-subtree roots to flag after the run completes.
    barriers: Vec<IrId>,
}

impl<'a> Analysis<'a> {
    fn new(ir: &'a Ir) -> Self {
        Self {
            ir,
            totality: vec![None; ir.arena.nodes().len()],
            collect_memo: HashMap::new(),
            collect_active: Vec::new(),
            marks: Vec::new(),
            barriers: Vec::new(),
        }
    }

    fn node(&self, id: IrId) -> Result<crate::ir::IrNode, StrictnessAnalysisError> {
        self.ir
            .arena
            .node(id)
            .copied()
            .ok_or(StrictnessAnalysisError::InvalidNode { id })
    }

    fn mark(&mut self, id: IrId, level: Strictness) {
        if level != Strictness::Unknown {
            self.marks.push((id, level));
        }
    }

    fn child_ids(
        &self,
        id: IrId,
        slice: IrChildSlice,
    ) -> Result<&'a [IrId], StrictnessAnalysisError> {
        self.ir
            .arena
            .child_slice(slice)
            .ok_or(StrictnessAnalysisError::InvalidChildSlice { id, slice })
    }

    fn bindings(
        &self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<&'a [crate::ir::IrBinding], StrictnessAnalysisError> {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })?;
        self.ir
            .bindings
            .get(start..end)
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })
    }

    fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
    ) -> Result<&'a [IrAttrPathSegment], StrictnessAnalysisError> {
        self.ir
            .attr_paths
            .get(path.index())
            .map(Box::as_ref)
            .ok_or(StrictnessAnalysisError::InvalidAttrPath { id, path })
    }

    /// Returns the computed totality bit for a node, failing closed to
    /// non-total when pass 1 has not covered the node.
    fn total(&self, id: IrId) -> bool {
        self.totality
            .get(id.index())
            .copied()
            .flatten()
            .unwrap_or(false)
    }
}

/// Enumerates every child edge of one node in evaluation-relevant order.
///
/// This enumeration is the single definition of the IR's child relation for
/// this analysis: the tree validation, the totality pass, and the demand walk
/// all agree on it by construction.
fn for_each_child(
    analysis_ir: &Ir,
    id: IrId,
    node: crate::ir::IrNode,
    f: &mut dyn FnMut(IrId) -> Result<(), StrictnessAnalysisError>,
) -> Result<(), StrictnessAnalysisError> {
    type Callback<'a> = &'a mut dyn FnMut(IrId) -> Result<(), StrictnessAnalysisError>;
    let visit_slice = |slice: IrChildSlice, f: Callback<'_>| {
        let children = analysis_ir
            .arena
            .child_slice(slice)
            .ok_or(StrictnessAnalysisError::InvalidChildSlice { id, slice })?;
        for child in children {
            f(*child)?;
        }
        Ok(())
    };
    let visit_bindings = |slice: IrBindingSlice, f: Callback<'_>| {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })?;
        let bindings = analysis_ir
            .bindings
            .get(start..end)
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })?;
        for binding in bindings {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                f(key)?;
            }
            f(binding.value)?;
        }
        Ok(())
    };
    let visit_path = |path: IrAttrPathId, f: Callback<'_>| {
        let segments = analysis_ir
            .attr_paths
            .get(path.index())
            .ok_or(StrictnessAnalysisError::InvalidAttrPath { id, path })?;
        for segment in segments.as_ref() {
            if let IrAttrPathSegment::Dynamic(segment) = segment {
                f(*segment)?;
            }
        }
        Ok(())
    };
    match node.data {
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::GlobalVar { .. }
        | IrData::Local { .. }
        | IrData::Upval { .. }
        | IrData::DialectScopeVar { .. } => Ok(()),
        IrData::SearchPath { search_path, .. } => {
            if let Some(search_path) = search_path {
                f(search_path)?;
            }
            Ok(())
        }
        IrData::Node(child) => f(child),
        IrData::Pair { first, second } => {
            f(first)?;
            f(second)
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            f(first)?;
            f(second)?;
            f(third)
        }
        IrData::Children(slice) => visit_slice(slice, f),
        IrData::Bindings(slice) => visit_bindings(slice, f),
        IrData::Binary { lhs, rhs, .. } => {
            f(lhs)?;
            f(rhs)
        }
        IrData::Unary { operand, .. } => f(operand),
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            f(receiver)?;
            visit_path(path, f)?;
            if let Some(default) = default {
                f(default)?;
            }
            Ok(())
        }
        IrData::HasAttr { receiver, path, .. } => {
            f(receiver)?;
            visit_path(path, f)
        }
        IrData::PrimOp { args, .. } => visit_slice(args, f),
        IrData::DialectNode { argument, .. } => f(argument),
        IrData::Lambda { pattern, body, .. } => {
            f(pattern)?;
            f(body)
        }
        IrData::Let { bindings, body, .. } => {
            visit_bindings(bindings, f)?;
            f(body)
        }
        IrData::AttrSet { bindings, .. } => visit_bindings(bindings, f),
        IrData::FormalSet { formals, .. } => visit_slice(formals, f),
        IrData::Formal { default, .. } => {
            if let Some(default) = default {
                f(default)?;
            }
            Ok(())
        }
    }
}

/// Returns whether the arena's child edges form a forest (every node has at
/// most one parent), which makes the reachable subgraph rooted at `ir.root` a
/// tree.
///
/// Per-execution demand claims and the frame-stack chase are only meaningful
/// when each node has a single evaluation context, so shared or cyclic IR is
/// declined rather than analyzed.
fn edges_form_tree(ir: &Ir) -> Result<bool, StrictnessAnalysisError> {
    let mut parents = vec![0u8; ir.arena.nodes().len()];
    for index in 0..ir.arena.nodes().len() {
        let id = IrId::new(index as u32);
        let node = *ir
            .arena
            .node(id)
            .ok_or(StrictnessAnalysisError::InvalidNode { id })?;
        let mut shared = false;
        for_each_child(ir, id, node, &mut |child| {
            if let Some(count) = parents.get_mut(child.index()) {
                *count = count.saturating_add(1);
                if *count > 1 {
                    shared = true;
                }
            }
            Ok(())
        })?;
        if shared {
            return Ok(false);
        }
    }
    Ok(parents.get(ir.root.index()).copied().unwrap_or(1) == 0)
}

fn validate_payload(id: IrId, node: crate::ir::IrNode) -> Result<(), StrictnessAnalysisError> {
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
        Err(StrictnessAnalysisError::InvalidPayload {
            id,
            kind: node.kind,
            expected: expected_payload(node.kind),
        })
    }
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
