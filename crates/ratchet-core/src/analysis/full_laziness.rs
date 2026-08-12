//! Full-laziness candidate discovery over lowered IR.
//!
//! This precursor only reports closed, pure static-key `let` binding values
//! nested under a lambda. It does not rewrite IR. Values whose forced body mentions any
//! local/upvalue, uses a dynamic-scope probe or primop, allocates nested thunks,
//! introduces nested frames, or carries non-speculable effects stay conservative
//! until the real let-floating pass can move groups together.

use thiserror::Error;

use crate::ir::{
    Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId, IrKind,
    IrShapeId,
};
use crate::scope::FrameId;
use crate::syntax::Symbol;

/// One static-key binding value that the precursor proved closed under an enclosing lambda.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullLazinessCandidate {
    /// The lambda whose body contains the candidate binding.
    pub lambda: IrId,
    /// The `let` expression that owns the candidate binding.
    pub let_node: IrId,
    /// The index of the candidate binding inside the owning `let` binding run.
    pub binding_index: usize,
    /// The candidate static binding key, preserved so rewrite consumers do not
    /// have to rediscover it from the binding table.
    pub key: IrAttrPathSegment,
    /// The binding value that can be considered by a future float-out rewrite.
    pub value: IrId,
}

/// Summary of one full-laziness candidate scan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FullLazinessAnalysisReport {
    /// Closed, pure binding values nested under lambdas.
    pub candidates: Vec<FullLazinessCandidate>,
}

/// Errors returned when full-laziness analysis sees malformed IR side tables.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FullLazinessAnalysisError {
    /// A node id did not exist in the arena.
    #[error("invalid IR node id {id:?}")]
    InvalidNode {
        /// The invalid node id.
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
    /// A symbol id did not resolve through the symbol table.
    #[error("invalid symbol {symbol:?} at IR node {id:?}")]
    InvalidSymbol {
        /// The node that referenced the invalid symbol.
        id: IrId,
        /// The invalid symbol id.
        symbol: Symbol,
    },
    /// A frame id did not resolve through the frame table.
    #[error("invalid frame {frame:?} at IR node {id:?}")]
    InvalidFrame {
        /// The node that referenced the invalid frame.
        id: IrId,
        /// The invalid frame id.
        frame: FrameId,
    },
    /// A shape id did not resolve through the shape table.
    #[error("invalid shape {shape:?} at IR node {id:?}")]
    InvalidShape {
        /// The node that referenced the invalid shape.
        id: IrId,
        /// The invalid shape id.
        shape: IrShapeId,
    },
    /// An attrset node's shape side table disagreed with its binding run.
    #[error("invalid attrset shape {shape:?} at IR node {id:?}")]
    InvalidAttrSetShape {
        /// The attrset node whose shape metadata did not match its bindings.
        id: IrId,
        /// The inconsistent shape id.
        shape: IrShapeId,
    },
    /// An attrset node's recursive flag disagreed with its frame metadata.
    #[error("invalid attrset frame metadata at IR node {id:?}")]
    InvalidAttrSetFrame {
        /// The attrset node whose frame metadata did not match its recursive flag.
        id: IrId,
    },
    /// A dynamic-scope chain id did not resolve through the with-chain table.
    #[error("invalid with-chain {chain} at IR node {id:?}")]
    InvalidWithChain {
        /// The node that referenced the invalid dynamic-scope chain.
        id: IrId,
        /// The invalid with-chain id.
        chain: u32,
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
}

/// Finds closed, pure static-key `let` binding values nested under lambdas.
///
/// This report-only precursor does not mutate the IR and does not claim general
/// full-laziness. It recognizes only values that are independent of every
/// lexical environment slot, so future rewrites can use the report as a safe
/// lower bound while the real float-in/float-out pass is still absent.
///
/// # Errors
///
/// Returns [`FullLazinessAnalysisError`] if reachable IR nodes, child slices,
/// binding slices, attribute paths, symbols, frames, shapes, with-chains, or
/// node payloads are malformed.
pub fn analyze_full_laziness(
    ir: &Ir,
) -> Result<FullLazinessAnalysisReport, FullLazinessAnalysisError> {
    FullLazinessAnalyzer::new(ir).run()
}

#[derive(Debug)]
struct FullLazinessAnalyzer<'a> {
    ir: &'a Ir,
    validation_visited: Vec<bool>,
    discovery_visited: Vec<bool>,
    report: FullLazinessAnalysisReport,
}

impl<'a> FullLazinessAnalyzer<'a> {
    fn new(ir: &'a Ir) -> Self {
        Self {
            ir,
            validation_visited: vec![false; ir.arena.nodes().len()],
            discovery_visited: vec![false; ir.arena.nodes().len()],
            report: FullLazinessAnalysisReport::default(),
        }
    }

    fn run(mut self) -> Result<FullLazinessAnalysisReport, FullLazinessAnalysisError> {
        self.validate_reachable(self.ir.root)?;
        self.discover(self.ir.root)?;
        Ok(self.report)
    }

    fn validate_reachable(&mut self, id: IrId) -> Result<(), FullLazinessAnalysisError> {
        let visited = self
            .validation_visited
            .get_mut(id.index())
            .ok_or(FullLazinessAnalysisError::InvalidNode { id })?;
        if *visited {
            return Ok(());
        }
        *visited = true;

        let node = *self.node(id)?;
        self.validate_node(id, node)?;
        for child in self.children(id, node)? {
            self.validate_reachable(child)?;
        }
        for child in self.validation_only_children(id, node)? {
            self.validate_reachable(child)?;
        }
        Ok(())
    }

    fn discover(&mut self, id: IrId) -> Result<(), FullLazinessAnalysisError> {
        let visited = self
            .discovery_visited
            .get_mut(id.index())
            .ok_or(FullLazinessAnalysisError::InvalidNode { id })?;
        if *visited {
            return Ok(());
        }
        *visited = true;

        let node = *self.node(id)?;
        self.validate_node(id, node)?;
        if matches!(
            node.kind,
            IrKind::ThunkAlloc | IrKind::FormalSet | IrKind::Formal
        ) {
            return Ok(());
        }
        if node.kind == IrKind::Lambda {
            let IrData::Lambda { pattern, body, .. } = node.data else {
                return Err(Self::invalid_payload(id, node.kind, "lambda payload"));
            };
            if self.is_simple_formal(pattern)? {
                self.collect_lambda_body(id, body)?;
            }
        }

        for child in self.children(id, node)? {
            self.discover(child)?;
        }
        Ok(())
    }

    fn collect_lambda_body(
        &mut self,
        lambda: IrId,
        id: IrId,
    ) -> Result<(), FullLazinessAnalysisError> {
        let node = *self.node(id)?;
        self.validate_node(id, node)?;
        if matches!(
            node.kind,
            IrKind::Lambda | IrKind::ThunkAlloc | IrKind::FormalSet | IrKind::Formal
        ) {
            return Ok(());
        }
        if let IrKind::Let = node.kind {
            let IrData::Let { bindings, body, .. } = node.data else {
                return Err(Self::invalid_payload(id, node.kind, "let payload"));
            };
            let bindings = self
                .bindings(id, bindings)?
                .iter()
                .enumerate()
                .filter_map(|(index, binding)| match binding.key {
                    IrAttrPathSegment::Static(key) => Some((index, key, binding.value)),
                    IrAttrPathSegment::Dynamic(_) => None,
                })
                .collect::<Vec<_>>();
            for (binding_index, key, value) in bindings {
                if self.is_closed_pure_value(value)? {
                    self.report.candidates.push(FullLazinessCandidate {
                        lambda,
                        let_node: id,
                        binding_index,
                        key: IrAttrPathSegment::Static(key),
                        value,
                    });
                }
            }
            self.collect_lambda_body(lambda, body)?;
            return Ok(());
        }

        for child in self.children(id, node)? {
            self.collect_lambda_body(lambda, child)?;
        }
        Ok(())
    }

    fn is_closed_pure_value(&self, root: IrId) -> Result<bool, FullLazinessAnalysisError> {
        let root_node = *self.node(root)?;
        self.validate_node(root, root_node)?;
        if !root_node.effect.is_speculable() {
            return Ok(false);
        }

        let mut visited = Vec::new();
        let mut stack = vec![self.root_thunk_body(root)?];
        while let Some(id) = stack.pop() {
            if visited.contains(&id.as_u32()) {
                continue;
            }
            visited.push(id.as_u32());

            let node = *self.node(id)?;
            self.validate_node(id, node)?;
            if !node.effect.is_speculable()
                || matches!(
                    node.kind,
                    IrKind::LocalVar
                        | IrKind::UpvalVar
                        | IrKind::GlobalVar
                        | IrKind::Lambda
                        | IrKind::Let
                        | IrKind::FormalSet
                        | IrKind::Formal
                        | IrKind::ThunkAlloc
                        | IrKind::Apply
                        | IrKind::PrimOp
                )
            {
                return Ok(false);
            }
            if matches!(
                node.data,
                IrData::Local { .. }
                    | IrData::Upval { .. }
                    | IrData::Lambda { .. }
                    | IrData::DialectScopeVar { .. }
            ) {
                return Ok(false);
            }
            if let IrData::AttrSet {
                recursive, frame, ..
            } = node.data
            {
                if recursive || frame.is_some() {
                    return Ok(false);
                }
            }
            stack.extend(self.children(id, node)?);
        }
        Ok(true)
    }

    fn root_thunk_body(&self, root: IrId) -> Result<IrId, FullLazinessAnalysisError> {
        let node = *self.node(root)?;
        self.validate_node(root, node)?;
        if node.kind != IrKind::ThunkAlloc {
            return Ok(root);
        }
        let IrData::Node(body) = node.data else {
            return Err(Self::invalid_payload(root, node.kind, "thunk body"));
        };
        Ok(body)
    }

    fn is_simple_formal(&self, id: IrId) -> Result<bool, FullLazinessAnalysisError> {
        let node = self.node(id)?;
        Ok(matches!(
            (node.kind, node.data),
            (IrKind::Formal, IrData::Formal { default: None, .. })
        ))
    }

    fn children(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<Vec<IrId>, FullLazinessAnalysisError> {
        self.validate_node(id, node)?;
        let mut children = Vec::new();
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. }
            | IrData::Local { .. }
            | IrData::Upval { .. } => {}
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
            IrData::Children(slice) => children.extend_from_slice(self.child_slice(id, slice)?),
            IrData::Bindings(slice) => {
                for binding in self.bindings(id, slice)? {
                    children.push(binding.value);
                    if let Some(dynamic) = self.validate_attr_path_segment(id, binding.key)? {
                        children.push(dynamic);
                    }
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
                children.extend(self.attr_path_children(id, path)?);
            }
            IrData::HasAttr { receiver, path, .. } => {
                children.push(receiver);
                children.extend(self.attr_path_children(id, path)?);
            }
            IrData::PrimOp { args, .. } => children.extend_from_slice(self.child_slice(id, args)?),
            IrData::DialectNode { argument, .. } => children.push(argument),
            IrData::DialectScopeVar { .. } => {}
            IrData::Lambda { pattern, body, .. } => {
                children.push(pattern);
                children.push(body);
            }
            IrData::Let { bindings, body, .. } => {
                for binding in self.bindings(id, bindings)? {
                    children.push(binding.value);
                    if let Some(dynamic) = self.validate_attr_path_segment(id, binding.key)? {
                        children.push(dynamic);
                    }
                }
                children.push(body);
            }
            IrData::AttrSet { bindings, .. } => {
                for binding in self.bindings(id, bindings)? {
                    children.push(binding.value);
                    if let Some(dynamic) = self.validate_attr_path_segment(id, binding.key)? {
                        children.push(dynamic);
                    }
                }
            }
            IrData::FormalSet { formals, .. } => {
                children.extend_from_slice(self.child_slice(id, formals)?);
            }
            IrData::Formal { default, .. } => children.extend(default),
        }
        Ok(children)
    }

    fn validation_only_children(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<Vec<IrId>, FullLazinessAnalysisError> {
        match node.data {
            IrData::DialectScopeVar { chain, .. } => {
                Ok(self.with_chain(id, chain)?.scopes.as_ref().to_vec())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn child_slice(
        &self,
        id: IrId,
        slice: IrChildSlice,
    ) -> Result<&[IrId], FullLazinessAnalysisError> {
        self.ir
            .arena
            .child_slice(slice)
            .ok_or(FullLazinessAnalysisError::InvalidChildSlice { id, slice })
    }

    fn bindings(
        &self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<&[crate::ir::IrBinding], FullLazinessAnalysisError> {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(FullLazinessAnalysisError::InvalidBindingSlice { id, slice })?;
        self.ir
            .bindings
            .get(start..end)
            .ok_or(FullLazinessAnalysisError::InvalidBindingSlice { id, slice })
    }

    fn attr_path_children(
        &self,
        id: IrId,
        path: IrAttrPathId,
    ) -> Result<Vec<IrId>, FullLazinessAnalysisError> {
        let path = self
            .ir
            .attr_paths
            .get(path.index())
            .ok_or(FullLazinessAnalysisError::InvalidAttrPath { id, path })?;
        Ok(path
            .iter()
            .filter_map(
                |segment| match self.validate_attr_path_segment(id, *segment) {
                    Ok(dynamic) => dynamic.map(Ok),
                    Err(error) => Some(Err(error)),
                },
            )
            .collect::<Result<Vec<_>, _>>()?)
    }

    fn node(&self, id: IrId) -> Result<&crate::ir::IrNode, FullLazinessAnalysisError> {
        self.ir
            .arena
            .node(id)
            .ok_or(FullLazinessAnalysisError::InvalidNode { id })
    }

    fn validate_node(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<(), FullLazinessAnalysisError> {
        self.validate_payload(id, node)?;
        self.validate_references(id, node)?;
        if let IrData::AttrSet {
            shape,
            bindings,
            has_dynamic,
            recursive,
            frame,
            ..
        } = node.data
        {
            if recursive != frame.is_some() {
                return Err(FullLazinessAnalysisError::InvalidAttrSetFrame { id });
            }
            self.validate_attrset_shape(id, shape, bindings, has_dynamic)?;
        }
        Ok(())
    }

    fn validate_references(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<(), FullLazinessAnalysisError> {
        match node.data {
            IrData::None | IrData::Int(_) | IrData::Float(_) | IrData::Bool(_) => Ok(()),
            IrData::Symbol(symbol) | IrData::GlobalVar { symbol, .. } => {
                self.check_symbol(id, symbol)
            }
            IrData::SearchPath {
                literal,
                search_path,
            } => {
                self.check_symbol(id, literal)?;
                if let Some(search_path) = search_path {
                    self.check_node_id(search_path)?;
                }
                Ok(())
            }
            IrData::Node(child) => self.check_node_id(child),
            IrData::Pair { first, second } => {
                self.check_node_id(first)?;
                self.check_node_id(second)
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                self.check_node_id(first)?;
                self.check_node_id(second)?;
                self.check_node_id(third)
            }
            IrData::Children(slice) => {
                for child in self.child_slice(id, slice)? {
                    self.check_node_id(*child)?;
                }
                Ok(())
            }
            IrData::Bindings(slice) => {
                for binding in self.bindings(id, slice)? {
                    self.validate_attr_path_segment(id, binding.key)?;
                    self.check_node_id(binding.value)?;
                }
                Ok(())
            }
            IrData::Binary { lhs, rhs, .. } => {
                self.check_node_id(lhs)?;
                self.check_node_id(rhs)
            }
            IrData::Unary { operand, .. } => self.check_node_id(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                self.check_node_id(receiver)?;
                if let Some(default) = default {
                    self.check_node_id(default)?;
                }
                self.attr_path_children(id, path)?;
                Ok(())
            }
            IrData::HasAttr { receiver, path, .. } => {
                self.check_node_id(receiver)?;
                self.attr_path_children(id, path)?;
                Ok(())
            }
            IrData::PrimOp { symbol, args } => {
                self.check_symbol(id, symbol)?;
                for child in self.child_slice(id, args)? {
                    self.check_node_id(*child)?;
                }
                Ok(())
            }
            IrData::DialectNode { argument, .. } => self.check_node_id(argument),
            IrData::DialectScopeVar { symbol, chain, .. } => {
                self.check_symbol(id, symbol)?;
                for scope in self.with_chain(id, chain)?.scopes.as_ref() {
                    self.check_node_id(*scope)?;
                }
                Ok(())
            }
            IrData::Lambda {
                pattern,
                body,
                frame,
            } => {
                self.check_node_id(pattern)?;
                self.check_node_id(body)?;
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                }
                Ok(())
            }
            IrData::Let {
                bindings,
                body,
                frame,
            } => {
                for binding in self.bindings(id, bindings)? {
                    self.validate_attr_path_segment(id, binding.key)?;
                    self.check_node_id(binding.value)?;
                }
                self.check_node_id(body)?;
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                }
                Ok(())
            }
            IrData::AttrSet {
                shape,
                bindings,
                frame,
                ..
            } => {
                self.check_shape(id, shape)?;
                for binding in self.bindings(id, bindings)? {
                    self.validate_attr_path_segment(id, binding.key)?;
                    self.check_node_id(binding.value)?;
                }
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                }
                Ok(())
            }
            IrData::FormalSet { formals, alias, .. } => {
                for formal in self.child_slice(id, formals)? {
                    self.check_node_id(*formal)?;
                }
                if let Some(alias) = alias {
                    self.check_symbol(id, alias)?;
                }
                Ok(())
            }
            IrData::Formal { name, default } => {
                self.check_symbol(id, name)?;
                if let Some(default) = default {
                    self.check_node_id(default)?;
                }
                Ok(())
            }
            IrData::Local { .. } | IrData::Upval { .. } => Ok(()),
        }
    }

    fn validate_attr_path_segment(
        &self,
        id: IrId,
        segment: IrAttrPathSegment,
    ) -> Result<Option<IrId>, FullLazinessAnalysisError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => {
                self.check_symbol(id, symbol)?;
                Ok(None)
            }
            IrAttrPathSegment::Dynamic(dynamic) => {
                self.check_node_id(dynamic)?;
                Ok(Some(dynamic))
            }
        }
    }

    fn validate_attrset_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
        bindings: IrBindingSlice,
        has_dynamic: bool,
    ) -> Result<(), FullLazinessAnalysisError> {
        let shape_table = self.check_shape(id, shape)?;
        let mut static_keys = Vec::new();
        let mut saw_dynamic = false;
        for binding in self.bindings(id, bindings)? {
            match binding.key {
                IrAttrPathSegment::Static(symbol) => static_keys.push(symbol),
                IrAttrPathSegment::Dynamic(_) => saw_dynamic = true,
            }
        }
        if shape_table.keys.as_ref() == static_keys.as_slice() && has_dynamic == saw_dynamic {
            Ok(())
        } else {
            Err(FullLazinessAnalysisError::InvalidAttrSetShape { id, shape })
        }
    }

    fn check_node_id(&self, id: IrId) -> Result<(), FullLazinessAnalysisError> {
        self.node(id).map(|_| ())
    }

    fn check_symbol(&self, id: IrId, symbol: Symbol) -> Result<(), FullLazinessAnalysisError> {
        if self.ir.symbols.resolve(symbol).is_some() {
            Ok(())
        } else {
            Err(FullLazinessAnalysisError::InvalidSymbol { id, symbol })
        }
    }

    fn check_frame(&self, id: IrId, frame: FrameId) -> Result<(), FullLazinessAnalysisError> {
        if self.ir.frames.get(frame.index()).is_some() {
            Ok(())
        } else {
            Err(FullLazinessAnalysisError::InvalidFrame { id, frame })
        }
    }

    fn check_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
    ) -> Result<&crate::ir::IrShape, FullLazinessAnalysisError> {
        self.ir
            .shapes
            .get(shape.index())
            .ok_or(FullLazinessAnalysisError::InvalidShape { id, shape })
    }

    fn with_chain(
        &self,
        id: IrId,
        chain: u32,
    ) -> Result<&crate::ir::IrWithChain, FullLazinessAnalysisError> {
        self.ir
            .with_chains
            .get(chain as usize)
            .ok_or(FullLazinessAnalysisError::InvalidWithChain { id, chain })
    }

    fn validate_payload(
        &self,
        id: IrId,
        node: crate::ir::IrNode,
    ) -> Result<(), FullLazinessAnalysisError> {
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
                expected_payload(node.kind),
            ))
        }
    }

    const fn invalid_payload(
        id: IrId,
        kind: IrKind,
        expected: &'static str,
    ) -> FullLazinessAnalysisError {
        FullLazinessAnalysisError::InvalidPayload { id, kind, expected }
    }
}

const fn expected_payload(kind: IrKind) -> &'static str {
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
