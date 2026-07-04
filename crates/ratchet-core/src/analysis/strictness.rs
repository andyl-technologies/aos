//! Strictness and demand analysis over lowered IR.
//!
//! This first pass is a conservative backward demand seed. It starts from the
//! demanded root expression, walks only through child positions that the
//! tree-walk evaluator must evaluate to WHNF, and annotates those nodes with
//! [`Strictness::Strict`]. It intentionally does not cross unknown function
//! calls, lazy list elements, attribute values, selected branches, or skipped
//! higher-order builtin callbacks.

use std::collections::HashSet;

use thiserror::Error;

use crate::builtins::{
    BuiltinExecution, DirectBinaryPrimOp, StrictBinaryPrimOp, StrictTernaryPrimOp, TraceMode,
    lookup_builtin,
};
use crate::ir::{
    Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId, IrKind,
    Strictness,
};
use crate::syntax::{BinOpKind, Symbol};

/// Summary of one strictness annotation run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrictnessAnalysisReport {
    /// Number of fact records changed from unknown to strict.
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

/// Annotates IR nodes that are proven to be demanded.
///
/// The pass mutates `ir.facts` in place and leaves all unproven nodes at their
/// previous fact value. It is safe to run repeatedly; already-strict nodes are
/// not counted as newly marked in the returned report.
///
/// # Errors
///
/// Returns [`StrictnessAnalysisError`] if an arena node payload does not match
/// its kind, or if the IR arena, child pool, frame table, binding table,
/// attribute-path table, symbol table, or fact table is internally inconsistent.
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
    StrictnessAnalyzer::new(ir).run()
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

#[derive(Debug)]
struct StrictnessAnalyzer<'a> {
    ir: &'a mut Ir,
    demanded: Vec<bool>,
    worklist: Vec<IrId>,
    report: StrictnessAnalysisReport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LocalDemandTarget {
    depth: u32,
    slot: u32,
}

impl LocalDemandTarget {
    const fn simple_lambda_argument() -> Self {
        Self { depth: 0, slot: 0 }
    }

    const fn enter_frame(self) -> Self {
        Self {
            depth: self.depth.saturating_add(1),
            slot: self.slot,
        }
    }
}

impl<'a> StrictnessAnalyzer<'a> {
    fn new(ir: &'a mut Ir) -> Self {
        let demanded = vec![false; ir.arena.nodes().len()];
        Self {
            ir,
            demanded,
            worklist: Vec::new(),
            report: StrictnessAnalysisReport::default(),
        }
    }

    fn run(mut self) -> Result<StrictnessAnalysisReport, StrictnessAnalysisError> {
        self.demand(self.ir.root)?;
        while let Some(id) = self.worklist.pop() {
            self.propagate_from(id)?;
        }
        Ok(self.report)
    }

    fn demand(&mut self, id: IrId) -> Result<(), StrictnessAnalysisError> {
        let demanded = self
            .demanded
            .get_mut(id.index())
            .ok_or(StrictnessAnalysisError::InvalidNode { id })?;
        if *demanded {
            return Ok(());
        }
        *demanded = true;
        let facts = self
            .ir
            .facts
            .get_mut(id)
            .ok_or(StrictnessAnalysisError::MissingFact { id })?;
        if facts.strictness != Strictness::Strict {
            facts.strictness = Strictness::Strict;
            self.report.nodes_marked_strict += 1;
        }
        self.worklist.push(id);
        Ok(())
    }

    fn propagate_from(&mut self, id: IrId) -> Result<(), StrictnessAnalysisError> {
        let successors = self.demanded_successors(id)?;
        for successor in successors {
            self.demand(successor)?;
        }
        Ok(())
    }

    fn demanded_successors(&self, id: IrId) -> Result<Vec<IrId>, StrictnessAnalysisError> {
        let node = *self.node(id)?;
        let mut successors = Vec::new();
        match node.kind {
            IrKind::Int
            | IrKind::Float
            | IrKind::Bool
            | IrKind::Null
            | IrKind::Str
            | IrKind::Path
            | IrKind::Uri
            | IrKind::LocalVar
            | IrKind::UpvalVar
            | IrKind::GlobalVar
            | IrKind::BuiltinAttr
            | IrKind::List
            | IrKind::Lambda
            | IrKind::FormalSet
            | IrKind::Formal => {}
            IrKind::SearchPath => {
                if let IrData::SearchPath {
                    search_path: Some(search_path),
                    ..
                } = node.data
                {
                    successors.push(search_path);
                }
            }
            IrKind::AttrSet => {
                if let IrData::AttrSet { bindings, .. } = node.data {
                    for binding in self.binding_values(id, bindings)? {
                        if let IrAttrPathSegment::Dynamic(key) = binding.key {
                            successors.push(key);
                        }
                    }
                }
            }
            IrKind::Apply => {
                if let IrData::Pair { first, second } = node.data {
                    successors.push(first);
                    if self.direct_lambda_demands_argument(first)? {
                        successors.push(second);
                    }
                }
            }
            IrKind::Select => {
                if let IrData::Select { receiver, path, .. } = node.data {
                    successors.push(receiver);
                    self.push_leading_dynamic_attr_segment(id, path, &mut successors)?;
                }
            }
            IrKind::HasAttr => {
                if let IrData::HasAttr { receiver, path, .. } = node.data {
                    successors.push(receiver);
                    self.push_leading_dynamic_attr_segment(id, path, &mut successors)?;
                }
            }
            IrKind::Let => {
                if let IrData::Let { body, .. } = node.data {
                    successors.push(body);
                }
            }
            IrKind::With => {
                if let IrData::Pair { second, .. } = node.data {
                    successors.push(second);
                }
            }
            IrKind::Assert => {
                if let IrData::Pair { first, .. } = node.data {
                    successors.push(first);
                }
            }
            IrKind::If => {
                if let IrData::Triple { first, .. } = node.data {
                    successors.push(first);
                }
            }
            IrKind::BinOp => {
                if let IrData::Binary { op, lhs, rhs } = node.data {
                    self.push_binary_successors(op, lhs, rhs, &mut successors);
                }
            }
            IrKind::UnaryOp => {
                if let IrData::Unary { operand, .. } = node.data {
                    successors.push(operand);
                }
            }
            IrKind::Interp => self.push_interp_successors(node.data, &mut successors, id)?,
            IrKind::ThunkAlloc => {
                if let IrData::Node(body) = node.data {
                    successors.push(body);
                }
            }
            IrKind::PrimOp => self.push_primop_successors(id, node.data, &mut successors)?,
        }
        Ok(successors)
    }

    fn push_binary_successors(
        &self,
        op: BinOpKind,
        lhs: IrId,
        rhs: IrId,
        successors: &mut Vec<IrId>,
    ) {
        match op {
            BinOpKind::And | BinOpKind::Or | BinOpKind::Impl => successors.push(lhs),
            BinOpKind::PipeRight => successors.push(rhs),
            BinOpKind::PipeLeft => successors.push(lhs),
            BinOpKind::Add
            | BinOpKind::Sub
            | BinOpKind::Mul
            | BinOpKind::Div
            | BinOpKind::Concat
            | BinOpKind::Update
            | BinOpKind::Lt
            | BinOpKind::Gt
            | BinOpKind::Le
            | BinOpKind::Ge
            | BinOpKind::Eq
            | BinOpKind::Ne => {
                successors.push(lhs);
                successors.push(rhs);
            }
        }
    }

    fn push_interp_successors(
        &self,
        data: IrData,
        successors: &mut Vec<IrId>,
        id: IrId,
    ) -> Result<(), StrictnessAnalysisError> {
        match data {
            IrData::Node(child) => successors.push(child),
            IrData::Children(children) => {
                successors.extend_from_slice(&self.child_ids(id, children)?)
            }
            IrData::None => {}
            _ => {}
        }
        Ok(())
    }

    fn push_primop_successors(
        &self,
        id: IrId,
        data: IrData,
        successors: &mut Vec<IrId>,
    ) -> Result<(), StrictnessAnalysisError> {
        match data {
            IrData::PrimOp { symbol, args } => {
                let args = self.child_ids(id, args)?;
                let name = self
                    .ir
                    .symbols
                    .resolve(symbol)
                    .ok_or(StrictnessAnalysisError::InvalidSymbol { id, symbol })?;
                let Some(builtin) = lookup_builtin(name) else {
                    return Ok(());
                };
                self.push_builtin_successors(builtin.execution(), &args, successors);
            }
            IrData::DialectNode { argument, .. } => successors.push(argument),
            IrData::DialectScopeVar { .. } => {}
            _ => {}
        }
        Ok(())
    }

    fn push_builtin_successors(
        &self,
        execution: BuiltinExecution,
        args: &[IrId],
        successors: &mut Vec<IrId>,
    ) {
        match execution {
            BuiltinExecution::Import
            | BuiltinExecution::Derivation
            | BuiltinExecution::GenericClosure
            | BuiltinExecution::TryEval
            | BuiltinExecution::Path
            | BuiltinExecution::PathExists
            | BuiltinExecution::ReadDir
            | BuiltinExecution::ReadFile
            | BuiltinExecution::ReadFileType
            | BuiltinExecution::FetchGit
            | BuiltinExecution::FetchMercurial
            | BuiltinExecution::FetchTarball
            | BuiltinExecution::FetchTree
            | BuiltinExecution::GetFlake
            | BuiltinExecution::Fetchurl
            | BuiltinExecution::FlakeRefToString
            | BuiltinExecution::ParseFlakeRef
            | BuiltinExecution::StrictUnary { .. } => self.push_arg(args, 0, successors),
            BuiltinExecution::ScopedImport
            | BuiltinExecution::FindFile
            | BuiltinExecution::FilterSource
            | BuiltinExecution::ToFile => self.push_args(args, &[0, 1], successors),
            BuiltinExecution::StrictBinary { primop, .. } => {
                self.push_strict_binary_successors(primop, args, successors);
            }
            BuiltinExecution::DirectBinary(primop) => {
                self.push_direct_binary_successors(primop, args, successors);
            }
            BuiltinExecution::DirectTernary(primop) => {
                self.push_strict_ternary_successors(primop, args, successors);
            }
            BuiltinExecution::Sort => self.push_arg(args, 1, successors),
            BuiltinExecution::Seq | BuiltinExecution::DeepSeq => self.push_arg(args, 0, successors),
            BuiltinExecution::AddErrorContext => self.push_arg(args, 1, successors),
            BuiltinExecution::Trace {
                mode: TraceMode::Always,
            }
            | BuiltinExecution::Warn => {
                self.push_arg(args, 0, successors);
            }
            BuiltinExecution::Trace {
                mode: TraceMode::Verbose,
            } => {}
            BuiltinExecution::DerivationStrict
            | BuiltinExecution::LazyUnary
            | BuiltinExecution::BuiltinsValue
            | BuiltinExecution::TrueValue
            | BuiltinExecution::FalseValue
            | BuiltinExecution::NullValue
            | BuiltinExecution::CurrentSystemValue
            | BuiltinExecution::CurrentTimeValue
            | BuiltinExecution::StoreDirValue
            | BuiltinExecution::NixVersionValue
            | BuiltinExecution::LangVersionValue
            | BuiltinExecution::NixPathValue => {}
        }
    }

    fn push_strict_binary_successors(
        &self,
        primop: StrictBinaryPrimOp,
        args: &[IrId],
        successors: &mut Vec<IrId>,
    ) {
        match primop {
            StrictBinaryPrimOp::All
            | StrictBinaryPrimOp::Any
            | StrictBinaryPrimOp::ConcatMap
            | StrictBinaryPrimOp::Filter
            | StrictBinaryPrimOp::GenList
            | StrictBinaryPrimOp::GroupBy
            | StrictBinaryPrimOp::Map
            | StrictBinaryPrimOp::Partition => self.push_arg(args, 1, successors),
            StrictBinaryPrimOp::AppendContext
            | StrictBinaryPrimOp::Add
            | StrictBinaryPrimOp::Sub
            | StrictBinaryPrimOp::Mul
            | StrictBinaryPrimOp::Div
            | StrictBinaryPrimOp::BitAnd
            | StrictBinaryPrimOp::BitOr
            | StrictBinaryPrimOp::BitXor
            | StrictBinaryPrimOp::CompareVersions
            | StrictBinaryPrimOp::ElemAt
            | StrictBinaryPrimOp::LessThan
            | StrictBinaryPrimOp::HashString
            | StrictBinaryPrimOp::HashFile
            | StrictBinaryPrimOp::Match
            | StrictBinaryPrimOp::Split => self.push_args(args, &[0, 1], successors),
        }
    }

    fn push_direct_binary_successors(
        &self,
        primop: DirectBinaryPrimOp,
        args: &[IrId],
        successors: &mut Vec<IrId>,
    ) {
        match primop {
            DirectBinaryPrimOp::Elem
            | DirectBinaryPrimOp::MapAttrs
            | DirectBinaryPrimOp::ZipAttrsWith => self.push_arg(args, 1, successors),
            DirectBinaryPrimOp::GetAttr
            | DirectBinaryPrimOp::HasAttr
            | DirectBinaryPrimOp::UnsafeGetAttrPos
            | DirectBinaryPrimOp::RemoveAttrs
            | DirectBinaryPrimOp::IntersectAttrs
            | DirectBinaryPrimOp::CatAttrs
            | DirectBinaryPrimOp::ConcatStringsSep => self.push_args(args, &[0, 1], successors),
        }
    }

    fn push_strict_ternary_successors(
        &self,
        primop: StrictTernaryPrimOp,
        args: &[IrId],
        successors: &mut Vec<IrId>,
    ) {
        match primop {
            StrictTernaryPrimOp::FoldlStrict => self.push_args(args, &[0, 2], successors),
            StrictTernaryPrimOp::ReplaceStrings | StrictTernaryPrimOp::Substring => {
                self.push_args(args, &[0, 1, 2], successors);
            }
        }
    }

    fn push_args(&self, args: &[IrId], indices: &[usize], successors: &mut Vec<IrId>) {
        for index in indices {
            self.push_arg(args, *index, successors);
        }
    }

    fn push_arg(&self, args: &[IrId], index: usize, successors: &mut Vec<IrId>) {
        if let Some(arg) = args.get(index).copied() {
            successors.push(arg);
        }
    }

    fn push_leading_dynamic_attr_segment(
        &self,
        id: IrId,
        path: IrAttrPathId,
        successors: &mut Vec<IrId>,
    ) -> Result<(), StrictnessAnalysisError> {
        if let Some(IrAttrPathSegment::Dynamic(segment)) = self.attr_path(id, path)?.first() {
            successors.push(*segment);
        }
        Ok(())
    }

    fn direct_lambda_demands_argument(
        &self,
        function: IrId,
    ) -> Result<bool, StrictnessAnalysisError> {
        let node = *self.node(function)?;
        let IrData::Lambda {
            pattern: pattern_id,
            body,
            frame,
        } = node.data
        else {
            return Ok(false);
        };
        let pattern_node = *self.node(pattern_id)?;
        match pattern_node.kind {
            IrKind::Formal => {
                let IrData::Formal { default: None, .. } = pattern_node.data else {
                    return Ok(false);
                };
                let mut probe = DemandProbe::new(self);
                probe.node_demands_target(body, LocalDemandTarget::simple_lambda_argument())
            }
            IrKind::FormalSet => {
                self.formal_set_pattern_forces_argument(function, pattern_id, pattern_node, frame)
            }
            _ => Ok(false),
        }
    }

    fn formal_set_pattern_forces_argument(
        &self,
        lambda: IrId,
        pattern_id: IrId,
        pattern: crate::ir::IrNode,
        frame: Option<crate::FrameId>,
    ) -> Result<bool, StrictnessAnalysisError> {
        let Some(frame) = frame else {
            return Ok(false);
        };
        let IrData::FormalSet { formals, alias, .. } = pattern.data else {
            return Err(StrictnessAnalysisError::InvalidPayload {
                id: pattern_id,
                kind: pattern.kind,
                expected: expected_payload(pattern.kind),
            });
        };
        let formal_ids = self.child_ids(pattern_id, formals)?;
        let mut names = Vec::new();
        for formal_id in formal_ids {
            let formal = *self.node(formal_id)?;
            if formal.kind != IrKind::Formal {
                return Err(StrictnessAnalysisError::InvalidPayload {
                    id: formal_id,
                    kind: formal.kind,
                    expected: expected_payload(IrKind::Formal),
                });
            }
            let IrData::Formal { name, .. } = formal.data else {
                return Err(StrictnessAnalysisError::InvalidPayload {
                    id: formal_id,
                    kind: formal.kind,
                    expected: expected_payload(formal.kind),
                });
            };
            if self.ir.symbols.resolve(name).is_none() {
                return Err(StrictnessAnalysisError::InvalidSymbol {
                    id: formal_id,
                    symbol: name,
                });
            }
            names.push(name);
        }
        if let Some(alias) = alias
            && self.ir.symbols.resolve(alias).is_none()
        {
            return Err(StrictnessAnalysisError::InvalidSymbol {
                id: lambda,
                symbol: alias,
            });
        }
        let alias_slot = alias.filter(|alias| !names.contains(alias));
        let pattern_slots = names.len() + usize::from(alias_slot.is_some());
        let slot_count = self
            .ir
            .frames
            .get(frame.index())
            .ok_or(StrictnessAnalysisError::InvalidFrame { id: lambda, frame })?
            .slot_count as usize;
        Ok(slot_count == pattern_slots)
    }

    fn child_ids(
        &self,
        id: IrId,
        slice: IrChildSlice,
    ) -> Result<Vec<IrId>, StrictnessAnalysisError> {
        self.ir
            .arena
            .child_slice(slice)
            .map(<[IrId]>::to_vec)
            .ok_or(StrictnessAnalysisError::InvalidChildSlice { id, slice })
    }

    fn binding_values(
        &self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<Vec<crate::ir::IrBinding>, StrictnessAnalysisError> {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })?;
        self.ir
            .bindings
            .get(start..end)
            .map(<[crate::ir::IrBinding]>::to_vec)
            .ok_or(StrictnessAnalysisError::InvalidBindingSlice { id, slice })
    }

    fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
    ) -> Result<&[IrAttrPathSegment], StrictnessAnalysisError> {
        self.ir
            .attr_paths
            .get(path.index())
            .map(Box::as_ref)
            .ok_or(StrictnessAnalysisError::InvalidAttrPath { id, path })
    }

    fn node(&self, id: IrId) -> Result<&crate::ir::IrNode, StrictnessAnalysisError> {
        self.ir
            .arena
            .node(id)
            .ok_or(StrictnessAnalysisError::InvalidNode { id })
    }
}

#[derive(Debug)]
struct DemandProbe<'a, 'b> {
    analyzer: &'a StrictnessAnalyzer<'b>,
    visiting: HashSet<(IrId, LocalDemandTarget)>,
}

impl<'a, 'b> DemandProbe<'a, 'b> {
    fn new(analyzer: &'a StrictnessAnalyzer<'b>) -> Self {
        Self {
            analyzer,
            visiting: HashSet::new(),
        }
    }

    fn node_demands_target(
        &mut self,
        id: IrId,
        target: LocalDemandTarget,
    ) -> Result<bool, StrictnessAnalysisError> {
        if !self.visiting.insert((id, target)) {
            return Ok(false);
        }
        let result = self.node_demands_target_inner(id, target);
        self.visiting.remove(&(id, target));
        result
    }

    fn node_demands_target_inner(
        &mut self,
        id: IrId,
        target: LocalDemandTarget,
    ) -> Result<bool, StrictnessAnalysisError> {
        let node = *self.analyzer.node(id)?;
        match node.kind {
            IrKind::LocalVar => {
                let IrData::Local { slot } = node.data else {
                    return Ok(false);
                };
                Ok(target.depth == 0 && target.slot == slot)
            }
            IrKind::UpvalVar => {
                let IrData::Upval { depth, slot } = node.data else {
                    return Ok(false);
                };
                Ok(target.depth == depth && target.slot == slot)
            }
            IrKind::Let => {
                let IrData::Let { body, .. } = node.data else {
                    return Ok(false);
                };
                self.node_demands_target(body, target.enter_frame())
            }
            IrKind::AttrSet => {
                let IrData::AttrSet {
                    bindings,
                    recursive,
                    ..
                } = node.data
                else {
                    return Ok(false);
                };
                let key_target = if recursive {
                    target.enter_frame()
                } else {
                    target
                };
                for binding in self.analyzer.binding_values(id, bindings)? {
                    if let IrAttrPathSegment::Dynamic(key) = binding.key
                        && self.node_demands_target(key, key_target)?
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            IrKind::Lambda | IrKind::FormalSet | IrKind::Formal | IrKind::List => Ok(false),
            IrKind::SearchPath => {
                if let IrData::SearchPath {
                    search_path: Some(search_path),
                    ..
                } = node.data
                {
                    return self.node_demands_target(search_path, target);
                }
                Ok(false)
            }
            IrKind::Apply => {
                let IrData::Pair { first, second } = node.data else {
                    return Ok(false);
                };
                if self.node_demands_target(first, target)? {
                    return Ok(true);
                }
                if self.analyzer.direct_lambda_demands_argument(first)? {
                    return self.node_demands_target(second, target);
                }
                Ok(false)
            }
            IrKind::Select => {
                let IrData::Select { receiver, path, .. } = node.data else {
                    return Ok(false);
                };
                if self.node_demands_target(receiver, target)? {
                    return Ok(true);
                }
                self.leading_dynamic_attr_segment_demands_target(id, path, target)
            }
            IrKind::HasAttr => {
                let IrData::HasAttr { receiver, path, .. } = node.data else {
                    return Ok(false);
                };
                if self.node_demands_target(receiver, target)? {
                    return Ok(true);
                }
                self.leading_dynamic_attr_segment_demands_target(id, path, target)
            }
            IrKind::With => {
                let IrData::Pair { second, .. } = node.data else {
                    return Ok(false);
                };
                self.node_demands_target(second, target)
            }
            IrKind::Assert => {
                let IrData::Pair { first, .. } = node.data else {
                    return Ok(false);
                };
                self.node_demands_target(first, target)
            }
            IrKind::If => {
                let IrData::Triple { first, .. } = node.data else {
                    return Ok(false);
                };
                self.node_demands_target(first, target)
            }
            IrKind::BinOp => {
                let IrData::Binary { op, lhs, rhs } = node.data else {
                    return Ok(false);
                };
                self.binary_demands_target(op, lhs, rhs, target)
            }
            IrKind::UnaryOp => {
                let IrData::Unary { operand, .. } = node.data else {
                    return Ok(false);
                };
                self.node_demands_target(operand, target)
            }
            IrKind::Interp => self.interp_demands_target(id, node.data, target),
            IrKind::ThunkAlloc => {
                let IrData::Node(body) = node.data else {
                    return Ok(false);
                };
                self.node_demands_target(body, target)
            }
            IrKind::PrimOp => self.primop_demands_target(id, node.data, target),
            IrKind::Int
            | IrKind::Float
            | IrKind::Bool
            | IrKind::Null
            | IrKind::Str
            | IrKind::Path
            | IrKind::Uri
            | IrKind::GlobalVar
            | IrKind::BuiltinAttr => Ok(false),
        }
    }

    fn binary_demands_target(
        &mut self,
        op: BinOpKind,
        lhs: IrId,
        rhs: IrId,
        target: LocalDemandTarget,
    ) -> Result<bool, StrictnessAnalysisError> {
        match op {
            BinOpKind::And | BinOpKind::Or | BinOpKind::Impl | BinOpKind::PipeLeft => {
                self.node_demands_target(lhs, target)
            }
            BinOpKind::PipeRight => self.node_demands_target(rhs, target),
            BinOpKind::Add
            | BinOpKind::Sub
            | BinOpKind::Mul
            | BinOpKind::Div
            | BinOpKind::Concat
            | BinOpKind::Update
            | BinOpKind::Lt
            | BinOpKind::Gt
            | BinOpKind::Le
            | BinOpKind::Ge
            | BinOpKind::Eq
            | BinOpKind::Ne => {
                Ok(self.node_demands_target(lhs, target)?
                    || self.node_demands_target(rhs, target)?)
            }
        }
    }

    fn interp_demands_target(
        &mut self,
        id: IrId,
        data: IrData,
        target: LocalDemandTarget,
    ) -> Result<bool, StrictnessAnalysisError> {
        match data {
            IrData::Node(child) => self.node_demands_target(child, target),
            IrData::Children(children) => {
                for child in self.analyzer.child_ids(id, children)? {
                    if self.node_demands_target(child, target)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            IrData::None => Ok(false),
            _ => Ok(false),
        }
    }

    fn primop_demands_target(
        &mut self,
        id: IrId,
        data: IrData,
        target: LocalDemandTarget,
    ) -> Result<bool, StrictnessAnalysisError> {
        let successors = self.analyzer.demanded_successors_for_probe(id, data)?;
        for successor in successors {
            if self.node_demands_target(successor, target)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn leading_dynamic_attr_segment_demands_target(
        &mut self,
        id: IrId,
        path: IrAttrPathId,
        target: LocalDemandTarget,
    ) -> Result<bool, StrictnessAnalysisError> {
        let Some(IrAttrPathSegment::Dynamic(segment)) = self.analyzer.attr_path(id, path)?.first()
        else {
            return Ok(false);
        };
        self.node_demands_target(*segment, target)
    }
}

impl StrictnessAnalyzer<'_> {
    fn demanded_successors_for_probe(
        &self,
        id: IrId,
        data: IrData,
    ) -> Result<Vec<IrId>, StrictnessAnalysisError> {
        let mut successors = Vec::new();
        self.push_primop_successors(id, data, &mut successors)?;
        Ok(successors)
    }
}
