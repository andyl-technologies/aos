//! Cardinality and usage analysis over lowered IR.
//!
//! This first pass is intentionally local. It recognizes simple `let` frames
//! whose same-frame slot uses can be counted syntactically, annotates binding
//! value nodes as [`Cardinality::Absent`] or [`Cardinality::Once`] when proven,
//! and leaves every obscured or multi-use binding at the conservative
//! [`Cardinality::Many`] default. It does not yet perform the whole-program
//! demand fixpoint or lower single-entry thunk representations.

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
/// The pass mutates `ir.facts` in place. It only refines `let` binding value
/// nodes when all uses of the frame can be counted without crossing another
/// frame-producing node.
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
        counter.count_node(body)?;
        for binding in &bindings {
            counter.count_node(binding.value)?;
        }
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
}

#[derive(Debug)]
struct LocalUsageCounter<'a, 'b> {
    analyzer: &'a CardinalityAnalyzer<'b>,
    counts: Vec<UsageCount>,
    complete: bool,
}

impl<'a, 'b> LocalUsageCounter<'a, 'b> {
    fn new(analyzer: &'a CardinalityAnalyzer<'b>, slots: usize) -> Self {
        Self {
            analyzer,
            counts: vec![UsageCount::Zero; slots],
            complete: true,
        }
    }

    fn count_node(&mut self, id: IrId) -> Result<(), CardinalityAnalysisError> {
        if !self.complete {
            return Ok(());
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
                let Some(count) = self.counts.get_mut(slot as usize) else {
                    self.complete = false;
                    return Ok(());
                };
                *count = count.increment();
            }
            IrKind::Let | IrKind::Lambda | IrKind::FormalSet | IrKind::Formal => {
                self.complete = false;
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
                if recursive {
                    self.complete = false;
                    return Ok(());
                }
                self.count_bindings(id, bindings)?;
            }
            _ => {
                for child in self.analyzer.child_nodes(id, node)? {
                    self.count_node(child)?;
                }
            }
        }
        Ok(())
    }

    fn count_bindings(
        &mut self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<(), CardinalityAnalysisError> {
        for binding in self.analyzer.binding_values(id, slice)? {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                self.count_node(key)?;
            }
            self.count_node(binding.value)?;
        }
        Ok(())
    }
}
