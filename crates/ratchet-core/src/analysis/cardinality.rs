//! Cardinality and usage analysis over lowered IR.
//!
//! The pass counts, per `let` frame, how many times each binding's slot can be
//! demanded during one execution of the frame, and annotates binding value
//! nodes as [`Cardinality::Absent`] or [`Cardinality::Once`] when proven. The
//! count is an upper bound: any position whose entry multiplicity cannot be
//! bounded contributes [`UsageCount::Many`].
//!
//! The counter walks *through* nested frames instead of giving up on them
//! (Phase 4 Chunk C widening):
//!
//! - references from a lambda body whose lambda is the direct callee of an
//!   application count exactly once per application (the body runs once);
//! - references from any other lambda body count as many-entry (the closure
//!   may be called any number of times), instead of poisoning the whole
//!   frame;
//! - nested `let` frames and recursive attribute-set frames count through
//!   with their depth shift: their binding-value thunks are update-shared, so
//!   each body executes at most once per frame execution;
//! - non-recursive attribute-set bindings were already counted in place.
//!
//! References to the analyzed frame's slots appear as [`IrData::Local`] at
//! nesting depth zero and as [`IrData::Upval`] whose depth equals the number
//! of intervening runtime frames; the walk tracks that depth exactly.

use thiserror::Error;

use crate::ir::{
    Cardinality, Ir, IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice,
    IrData, IrId, IrKind,
};

/// Summary of one cardinality annotation run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CardinalityAnalysisReport {
    /// Number of fact records changed to absent.
    pub nodes_marked_absent: usize,
    /// Number of fact records changed to once.
    pub nodes_marked_once: usize,
}

/// Errors returned when cardinality analysis sees malformed IR storage.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CardinalityAnalysisError {
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
    /// The fact table length did not match the arena node count.
    #[error("invalid fact table length: expected {expected}, got {actual}")]
    InvalidFactTableLength {
        /// The number of fact records required by the arena.
        expected: usize,
        /// The number of fact records present.
        actual: usize,
    },
}

/// Annotates binding values whose local usage cardinality is proven.
///
/// The pass mutates `ir.facts` in place. Slot uses are counted through nested
/// pure expressions, nested frames (with exact depth adjustment), directly
/// applied lambda bodies (once per application), other lambda bodies (as
/// many-entry uses), and attribute-set bindings. Any structurally uncountable
/// shape leaves the frame's bindings at the conservative
/// [`Cardinality::Many`] default.
///
/// # Errors
///
/// Returns [`CardinalityAnalysisError`] if the IR arena, child pool, binding
/// table, attribute-path table, fact table, or node payloads are internally
/// inconsistent.
pub fn annotate_cardinality(
    ir: &mut Ir,
) -> Result<CardinalityAnalysisReport, CardinalityAnalysisError> {
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(CardinalityAnalysisError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }
    CardinalityAnalyzer::new(ir).run()
}

#[derive(Debug)]
struct CardinalityAnalyzer<'a> {
    ir: &'a mut Ir,
    visited: Vec<bool>,
    report: CardinalityAnalysisReport,
}

impl<'a> CardinalityAnalyzer<'a> {
    fn new(ir: &'a mut Ir) -> Self {
        let visited = vec![false; ir.arena.nodes().len()];
        Self {
            ir,
            visited,
            report: CardinalityAnalysisReport::default(),
        }
    }

    fn run(mut self) -> Result<CardinalityAnalysisReport, CardinalityAnalysisError> {
        self.validate_payloads()?;
        self.visit(self.ir.root)?;
        Ok(self.report)
    }

    fn validate_payloads(&self) -> Result<(), CardinalityAnalysisError> {
        for index in 0..self.ir.arena.nodes().len() {
            let id = IrId::new(index as u32);
            let node = *self.node(id)?;
            self.validate_payload(id, node)?;
        }
        Ok(())
    }

    fn visit(&mut self, id: IrId) -> Result<(), CardinalityAnalysisError> {
        let visited = self
            .visited
            .get_mut(id.index())
            .ok_or(CardinalityAnalysisError::InvalidNode { id })?;
        if *visited {
            return Ok(());
        }
        *visited = true;

        let node = *self.node(id)?;
        match node.kind {
            IrKind::Let => {
                let IrData::Let { bindings, body, .. } = node.data else {
                    return Err(Self::invalid_payload(id, node.kind, "let payload"));
                };
                self.annotate_let_bindings(id, bindings, body)?;
                self.visit_bindings(id, bindings)?;
                self.visit(body)?;
            }
            _ => {
                for child in self.child_nodes(id, node)? {
                    self.visit(child)?;
                }
            }
        }
        Ok(())
    }

    fn annotate_let_bindings(
        &mut self,
        id: IrId,
        bindings: IrBindingSlice,
        body: IrId,
    ) -> Result<(), CardinalityAnalysisError> {
        let bindings = self.binding_values(id, bindings)?;
        let mut counter = LocalUsageCounter::new(self, bindings.len());
        counter.count_node(body, 0, UseMultiplicity::Once)?;
        counter.count_demanded_binding_values(&bindings)?;
        if !counter.complete {
            for binding in &bindings {
                self.set_cardinality(binding.value, Cardinality::Many)?;
            }
            return Ok(());
        }
        let cardinalities: Vec<Cardinality> = counter
            .counts
            .iter()
            .map(|count| match count {
                UsageCount::Zero => Cardinality::Absent,
                UsageCount::One => Cardinality::Once,
                UsageCount::Many => Cardinality::Many,
            })
            .collect();
        drop(counter);
        for (binding, cardinality) in bindings.iter().zip(cardinalities) {
            self.set_cardinality(binding.value, cardinality)?;
        }
        Ok(())
    }

    fn set_cardinality(
        &mut self,
        id: IrId,
        cardinality: Cardinality,
    ) -> Result<(), CardinalityAnalysisError> {
        let facts = self
            .ir
            .facts
            .get_mut(id)
            .ok_or(CardinalityAnalysisError::MissingFact { id })?;
        if facts.cardinality == cardinality {
            return Ok(());
        }
        facts.cardinality = cardinality;
        match cardinality {
            Cardinality::Absent => self.report.nodes_marked_absent += 1,
            Cardinality::Once => self.report.nodes_marked_once += 1,
            Cardinality::Many => {}
        }
        Ok(())
    }

    fn visit_bindings(
        &mut self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<(), CardinalityAnalysisError> {
        for binding in self.binding_values(id, slice)? {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                self.visit(key)?;
            }
            self.visit(binding.value)?;
        }
        Ok(())
    }

    fn child_nodes(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<Vec<IrId>, CardinalityAnalysisError> {
        self.validate_payload(id, node)?;
        let mut children = Vec::new();
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. }
            | IrData::Local { .. }
            | IrData::Upval { .. }
            | IrData::DialectScopeVar { .. } => {}
            IrData::SearchPath { search_path, .. } => children.extend(search_path),
            IrData::Node(child) => children.push(child),
            IrData::Pair { first, second } => {
                children.push(first);
                children.push(second);
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                children.push(first);
                children.push(second);
                children.push(third);
            }
            IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
                children.extend(self.child_ids(id, slice)?);
            }
            IrData::Bindings(slice) => {
                for binding in self.binding_values(id, slice)? {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        children.push(key);
                    }
                    children.push(binding.value);
                }
            }
            IrData::Binary { lhs, rhs, .. } => {
                children.push(lhs);
                children.push(rhs);
            }
            IrData::Unary { operand, .. } => children.push(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                children.push(receiver);
                children.extend(default);
                children.extend(self.dynamic_attr_path_segments(id, path)?);
            }
            IrData::HasAttr { receiver, path, .. } => {
                children.push(receiver);
                children.extend(self.dynamic_attr_path_segments(id, path)?);
            }
            IrData::DialectNode { argument, .. } => children.push(argument),
            IrData::Lambda { pattern, body, .. } => {
                children.push(pattern);
                children.push(body);
            }
            IrData::Let { bindings, body, .. } => {
                for binding in self.binding_values(id, bindings)? {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        children.push(key);
                    }
                    children.push(binding.value);
                }
                children.push(body);
            }
            IrData::AttrSet { bindings, .. } => {
                for binding in self.binding_values(id, bindings)? {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        children.push(key);
                    }
                    children.push(binding.value);
                }
            }
            IrData::FormalSet { formals, .. } => children.extend(self.child_ids(id, formals)?),
            IrData::Formal { default, .. } => children.extend(default),
        }
        Ok(children)
    }

    fn validate_payload(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<(), CardinalityAnalysisError> {
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
            IrKind::Apply | IrKind::With | IrKind::Assert => {
                matches!(node.data, IrData::Pair { .. })
            }
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
            Err(Self::invalid_payload(
                id,
                node.kind,
                Self::expected_payload(node.kind),
            ))
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

    fn dynamic_attr_path_segments(
        &self,
        id: IrId,
        path: IrAttrPathId,
    ) -> Result<Vec<IrId>, CardinalityAnalysisError> {
        Ok(self
            .attr_path(id, path)?
            .iter()
            .filter_map(|segment| match segment {
                IrAttrPathSegment::Static(_) => None,
                IrAttrPathSegment::Dynamic(dynamic) => Some(*dynamic),
            })
            .collect())
    }

    fn child_ids(
        &self,
        id: IrId,
        slice: IrChildSlice,
    ) -> Result<Vec<IrId>, CardinalityAnalysisError> {
        self.ir
            .arena
            .child_slice(slice)
            .map(<[IrId]>::to_vec)
            .ok_or(CardinalityAnalysisError::InvalidChildSlice { id, slice })
    }

    fn binding_values(
        &self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<Vec<IrBinding>, CardinalityAnalysisError> {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(CardinalityAnalysisError::InvalidBindingSlice { id, slice })?;
        self.ir
            .bindings
            .get(start..end)
            .map(<[IrBinding]>::to_vec)
            .ok_or(CardinalityAnalysisError::InvalidBindingSlice { id, slice })
    }

    fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
    ) -> Result<&[IrAttrPathSegment], CardinalityAnalysisError> {
        self.ir
            .attr_paths
            .get(path.index())
            .map(Box::as_ref)
            .ok_or(CardinalityAnalysisError::InvalidAttrPath { id, path })
    }

    fn node(&self, id: IrId) -> Result<&crate::ir::IrNode, CardinalityAnalysisError> {
        self.ir
            .arena
            .node(id)
            .ok_or(CardinalityAnalysisError::InvalidNode { id })
    }

    fn invalid_payload(id: IrId, kind: IrKind, expected: &'static str) -> CardinalityAnalysisError {
        CardinalityAnalysisError::InvalidPayload { id, kind, expected }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UsageCount {
    Zero,
    One,
    Many,
}

impl UsageCount {
    const fn increment(self) -> Self {
        match self {
            Self::Zero => Self::One,
            Self::One | Self::Many => Self::Many,
        }
    }

    const fn max(self, other: Self) -> Self {
        match (self, other) {
            (Self::Many, _) | (_, Self::Many) => Self::Many,
            (Self::One, _) | (_, Self::One) => Self::One,
            (Self::Zero, Self::Zero) => Self::Zero,
        }
    }
}

/// How many times one syntactic position may be entered per frame execution.
///
/// A [`UseMultiplicity::Once`] position runs at most once whenever the
/// analyzed frame executes once (bodies, direct-call lambda bodies, lazy
/// binding-value thunks). A [`UseMultiplicity::Many`] position may run any
/// number of times (bodies of closures that escape into unknown call sites).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UseMultiplicity {
    Once,
    Many,
}

/// Node-visit budget per analyzed frame.
///
/// The counter walks through nested frames, so an enormous frame subtree
/// (machine-generated modules, the whole-package attrset spine) could make
/// per-frame counting super-linear across deeply nested `let`s. Exhausting
/// the budget marks the count incomplete, which keeps every binding of the
/// frame at the conservative [`Cardinality::Many`] — the same failure mode
/// as any other uncountable shape.
const FRAME_COUNT_BUDGET: usize = 4096;

#[derive(Debug)]
struct LocalUsageCounter<'a, 'b> {
    analyzer: &'a CardinalityAnalyzer<'b>,
    counts: Vec<UsageCount>,
    complete: bool,
    budget: usize,
}

impl<'a, 'b> LocalUsageCounter<'a, 'b> {
    fn new(analyzer: &'a CardinalityAnalyzer<'b>, slots: usize) -> Self {
        Self {
            analyzer,
            counts: vec![UsageCount::Zero; slots],
            complete: true,
            budget: FRAME_COUNT_BUDGET,
        }
    }

    fn record_use(&mut self, slot: usize, multiplicity: UseMultiplicity) {
        let Some(count) = self.counts.get_mut(slot) else {
            self.complete = false;
            return;
        };
        *count = match multiplicity {
            UseMultiplicity::Once => count.increment(),
            UseMultiplicity::Many => UsageCount::Many,
        };
    }

    /// Counts uses of the analyzed frame's slots inside `id`.
    ///
    /// `depth` is the number of runtime frames between the analyzed frame and
    /// the position being counted (0 inside the frame's own body/values), so
    /// a slot use appears as `Local` at depth 0 and as `Upval` whose depth
    /// field equals `depth` otherwise. `multiplicity` bounds how many times
    /// this position may execute per frame execution.
    fn count_node(
        &mut self,
        id: IrId,
        depth: u32,
        multiplicity: UseMultiplicity,
    ) -> Result<(), CardinalityAnalysisError> {
        if !self.complete {
            return Ok(());
        }
        match self.budget.checked_sub(1) {
            Some(remaining) => self.budget = remaining,
            None => {
                self.complete = false;
                return Ok(());
            }
        }
        let node = *self.analyzer.node(id)?;
        match node.kind {
            IrKind::LocalVar => {
                let IrData::Local { slot } = node.data else {
                    return Err(CardinalityAnalyzer::invalid_payload(
                        id,
                        node.kind,
                        "local slot payload",
                    ));
                };
                if depth == 0 {
                    self.record_use(slot as usize, multiplicity);
                }
            }
            IrKind::UpvalVar => {
                let IrData::Upval {
                    depth: upval_depth,
                    slot,
                } = node.data
                else {
                    return Err(CardinalityAnalyzer::invalid_payload(
                        id,
                        node.kind,
                        "upvalue slot payload",
                    ));
                };
                if upval_depth == depth {
                    self.record_use(slot as usize, multiplicity);
                }
            }
            IrKind::Apply => {
                let IrData::Pair {
                    first: callee,
                    second: argument,
                } = node.data
                else {
                    return Err(CardinalityAnalyzer::invalid_payload(
                        id,
                        node.kind,
                        "pair payload",
                    ));
                };
                self.count_apply(callee, argument, depth, multiplicity)?;
            }
            IrKind::Lambda => {
                // A closure whose call sites are unknown may run any number
                // of times; its body's slot uses saturate instead of
                // poisoning the frame.
                self.count_lambda(id, node, depth, UseMultiplicity::Many)?;
            }
            IrKind::Let => {
                let IrData::Let { bindings, body, .. } = node.data else {
                    return Err(CardinalityAnalyzer::invalid_payload(
                        id,
                        node.kind,
                        "let payload",
                    ));
                };
                // A nested `let` pushes one runtime frame around both its
                // binding values and its body. Each binding value is an
                // update-shared thunk, so its body runs at most once per
                // frame execution; counting every value (demanded or not) is
                // a sound upper bound.
                self.count_bindings(id, bindings, depth + 1, multiplicity)?;
                self.count_node(body, depth + 1, multiplicity)?;
            }
            IrKind::If => {
                let IrData::Triple {
                    first: condition,
                    second: then_branch,
                    third: else_branch,
                } = node.data
                else {
                    return Err(CardinalityAnalyzer::invalid_payload(
                        id,
                        node.kind,
                        "triple payload",
                    ));
                };
                self.count_node(condition, depth, multiplicity)?;
                self.count_conditional_branches(then_branch, else_branch, depth, multiplicity)?;
            }
            IrKind::AttrSet => {
                let IrData::AttrSet {
                    bindings,
                    recursive,
                    ..
                } = node.data
                else {
                    return Err(CardinalityAnalyzer::invalid_payload(
                        id,
                        node.kind,
                        "attrset payload",
                    ));
                };
                // A recursive attrset pushes one runtime frame around its
                // binding values; a plain literal evaluates them in place.
                // Either way each value thunk is update-shared and runs at
                // most once per frame execution.
                let binding_depth = if recursive { depth + 1 } else { depth };
                self.count_bindings(id, bindings, binding_depth, multiplicity)?;
            }
            IrKind::FormalSet | IrKind::Formal => {
                // Patterns are only reachable through their lambda, which
                // counts them explicitly with the body's frame depth. A
                // pattern in any other position is uncountable.
                self.complete = false;
            }
            _ => {
                for child in self.analyzer.child_nodes(id, node)? {
                    self.count_node(child, depth, multiplicity)?;
                }
            }
        }
        Ok(())
    }

    /// Counts an application, running a directly applied lambda body once.
    ///
    /// `(x: body) arg` executes `body` exactly once per evaluation of the
    /// application, so outer-frame uses inside `body` count at the call
    /// site's multiplicity instead of saturating to many.
    fn count_apply(
        &mut self,
        callee: IrId,
        argument: IrId,
        depth: u32,
        multiplicity: UseMultiplicity,
    ) -> Result<(), CardinalityAnalysisError> {
        self.count_node(argument, depth, multiplicity)?;
        let callee_node = *self.analyzer.node(callee)?;
        if callee_node.kind == IrKind::Lambda {
            self.count_lambda(callee, callee_node, depth, multiplicity)
        } else {
            self.count_node(callee, depth, multiplicity)
        }
    }

    /// Counts a lambda's pattern defaults and body at their frame depth.
    ///
    /// The lambda's runtime frame sits between the analyzed frame and the
    /// body, so both the body and formal-default expressions count at
    /// `depth + 1`. Defaults run at most once per call, so they share the
    /// body's multiplicity.
    fn count_lambda(
        &mut self,
        id: IrId,
        node: crate::ir::IrNode,
        depth: u32,
        multiplicity: UseMultiplicity,
    ) -> Result<(), CardinalityAnalysisError> {
        let IrData::Lambda { pattern, body, .. } = node.data else {
            return Err(CardinalityAnalyzer::invalid_payload(
                id,
                node.kind,
                "lambda payload",
            ));
        };
        self.count_pattern(pattern, depth + 1, multiplicity)?;
        self.count_node(body, depth + 1, multiplicity)
    }

    fn count_pattern(
        &mut self,
        pattern: IrId,
        depth: u32,
        multiplicity: UseMultiplicity,
    ) -> Result<(), CardinalityAnalysisError> {
        if !self.complete {
            return Ok(());
        }
        let node = *self.analyzer.node(pattern)?;
        match (node.kind, node.data) {
            (IrKind::Formal, IrData::Formal { default, .. }) => {
                if let Some(default) = default {
                    self.count_node(default, depth, multiplicity)?;
                }
                Ok(())
            }
            (IrKind::FormalSet, IrData::FormalSet { formals, .. }) => {
                for formal in self.analyzer.child_ids(pattern, formals)? {
                    self.count_pattern(formal, depth, multiplicity)?;
                }
                Ok(())
            }
            _ => {
                self.complete = false;
                Ok(())
            }
        }
    }

    fn count_conditional_branches(
        &mut self,
        then_branch: IrId,
        else_branch: IrId,
        depth: u32,
        multiplicity: UseMultiplicity,
    ) -> Result<(), CardinalityAnalysisError> {
        // Branches are mutually exclusive, but both inherit the condition's
        // already-counted slot uses. Measure each branch delta from that shared
        // baseline, then apply the larger possible branch contribution.
        let counts_before_branches = self.counts.clone();

        self.count_node(then_branch, depth, multiplicity)?;
        if !self.complete {
            return Ok(());
        }
        let then_counts = self.counts.clone();

        self.counts = counts_before_branches.clone();
        self.count_node(else_branch, depth, multiplicity)?;
        if !self.complete {
            return Ok(());
        }
        let else_counts = self.counts.clone();

        self.counts = counts_before_branches
            .iter()
            .zip(then_counts.iter().zip(else_counts.iter()))
            .map(|(before, (then_count, else_count))| {
                let then_delta = usage_delta(*before, *then_count);
                let else_delta = usage_delta(*before, *else_count);
                apply_usage_delta(*before, then_delta.max(else_delta))
            })
            .collect();
        Ok(())
    }

    fn count_demanded_binding_values(
        &mut self,
        bindings: &[IrBinding],
    ) -> Result<(), CardinalityAnalysisError> {
        // A lazy binding value can only demand other same-frame slots after the
        // binding itself is reachable. Count each demanded value body once to
        // match update-thunk sharing, then keep propagating through new demands.
        let mut counted_values = vec![false; bindings.len()];
        loop {
            if !self.complete {
                return Ok(());
            }
            let Some(slot) = self.next_uncounted_demanded_binding(&counted_values) else {
                return Ok(());
            };
            counted_values[slot] = true;
            self.count_node(bindings[slot].value, 0, UseMultiplicity::Once)?;
        }
    }

    fn next_uncounted_demanded_binding(&self, counted_values: &[bool]) -> Option<usize> {
        self.counts
            .iter()
            .zip(counted_values.iter())
            .position(|(count, counted)| !*counted && *count != UsageCount::Zero)
    }

    fn count_bindings(
        &mut self,
        id: IrId,
        slice: IrBindingSlice,
        depth: u32,
        multiplicity: UseMultiplicity,
    ) -> Result<(), CardinalityAnalysisError> {
        for binding in self.analyzer.binding_values(id, slice)? {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                self.count_node(key, depth, multiplicity)?;
            }
            self.count_node(binding.value, depth, multiplicity)?;
        }
        Ok(())
    }
}

fn usage_delta(before: UsageCount, after: UsageCount) -> UsageCount {
    match (before, after) {
        (UsageCount::Zero, UsageCount::Zero)
        | (UsageCount::One, UsageCount::One)
        | (UsageCount::Many, UsageCount::Many) => UsageCount::Zero,
        (UsageCount::Zero, UsageCount::One) | (UsageCount::One, UsageCount::Many) => {
            UsageCount::One
        }
        (UsageCount::Zero, UsageCount::Many) => UsageCount::Many,
        // Backwards deltas are unreachable for normal counting; keep them
        // conservative if malformed control flow ever produces one.
        (UsageCount::One, UsageCount::Zero)
        | (UsageCount::Many, UsageCount::Zero)
        | (UsageCount::Many, UsageCount::One) => UsageCount::Many,
    }
}

fn apply_usage_delta(before: UsageCount, delta: UsageCount) -> UsageCount {
    match delta {
        UsageCount::Zero => before,
        UsageCount::One => before.increment(),
        UsageCount::Many => UsageCount::Many,
    }
}
