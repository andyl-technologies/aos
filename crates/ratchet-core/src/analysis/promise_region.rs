//! Conservative whole-demand region planning over lowered evaluator IR.
//!
//! The planner is a read-only precursor to a Promise/PIR execution tier. It
//! validates the reachable IR graph first, then discovers the largest region
//! that can retain allocations as virtual objects without crossing an
//! observable, dynamic, or otherwise unsupported boundary. Nodes are
//! specialized by their lexical frame signature; no IR node or fact is
//! rewritten.

use std::collections::{HashSet, VecDeque};

use thiserror::Error;

use crate::ir::{
    Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId, IrKind,
    IrNode, IrShapeId,
};
use crate::scope::FrameId;
use crate::syntax::Symbol;

/// The default maximum number of lexical-frame specializations for one IR node.
pub const DEFAULT_PROMISE_REGION_SPECIALIZATION_CAP: usize = 8;

/// Selects the symbol table that already validated reachable symbol ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PromiseRegionSymbolValidation {
    /// Validates every symbol against [`Ir::symbols`].
    #[default]
    IrTable,
    /// Trusts that an embedding runtime remapped and validated every symbol.
    ///
    /// This mode is for evaluators that replace module-local symbol ids with
    /// ids from a process-global table before planning. It does not suppress
    /// any other IR or side-table validation.
    ExternallyRemapped,
}

/// Configuration for conservative Promise/PIR region discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromiseRegionOptions {
    /// The maximum number of distinct frame signatures admitted for one IR node.
    pub specialization_cap: usize,
    /// The symbol-table validation contract for this IR artifact.
    pub symbol_validation: PromiseRegionSymbolValidation,
}

impl Default for PromiseRegionOptions {
    fn default() -> Self {
        Self {
            specialization_cap: DEFAULT_PROMISE_REGION_SPECIALIZATION_CAP,
            symbol_validation: PromiseRegionSymbolValidation::IrTable,
        }
    }
}

/// A lowered node paired with the lexical-frame signature used to plan it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PromiseRegionKey {
    /// The underlying lowered IR node.
    pub node: IrId,
    /// The active lexical frame, or `None` for the root environment.
    pub frame: Option<FrameId>,
}

/// The kind of virtual allocation retained inside a planned region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VirtualAllocationKind {
    /// A lazy promise represented by a `ThunkAlloc` node.
    Promise,
    /// A lexical environment frame.
    Frame,
    /// A lambda closure.
    Closure,
    /// A persistent list value.
    List,
    /// A static, nonrecursive attribute set.
    Attrs,
}

/// Counts virtual allocation sites by their representation kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtualAllocationCounts {
    /// Lazy promise allocation sites.
    pub promises: usize,
    /// Lexical frame allocation sites.
    pub frames: usize,
    /// Closure allocation sites.
    pub closures: usize,
    /// List allocation sites.
    pub lists: usize,
    /// Attribute-set allocation sites.
    pub attrs: usize,
}

impl VirtualAllocationCounts {
    fn record(&mut self, kind: VirtualAllocationKind) {
        match kind {
            VirtualAllocationKind::Promise => self.promises += 1,
            VirtualAllocationKind::Frame => self.frames += 1,
            VirtualAllocationKind::Closure => self.closures += 1,
            VirtualAllocationKind::List => self.lists += 1,
            VirtualAllocationKind::Attrs => self.attrs += 1,
        }
    }

    /// Returns the total number of virtual allocation sites.
    pub const fn total(self) -> usize {
        self.promises + self.frames + self.closures + self.lists + self.attrs
    }
}

/// Why execution must materialize state and return to the oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PromiseStatepointKind {
    /// The node carries a non-speculable effect stamp.
    Effect,
    /// A global lookup depends on runtime scope.
    Global,
    /// A `with` or dialect scope lookup depends on dynamic scope.
    DynamicScope,
    /// A dialect-owned operation has no engine-level semantics.
    Dialect,
    /// An attribute set is recursive.
    RecursiveAttrSet,
    /// An attribute set contains a dynamic key.
    DynamicAttrSet,
    /// A lambda uses a formal-set parameter pattern.
    FormalSetLambda,
    /// An attribute path contains a dynamic segment.
    DynamicSelect,
    /// An attribute selection supplies an `or` default.
    DefaultSelect,
    /// The application target is not a statically visible lambda.
    UnknownCall,
    /// The valid node kind is not yet a Promise/PIR region form.
    Unsupported,
}

/// How one frame-specialized node participates in the planned region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromiseRegionDisposition {
    /// The operation executes inside the native region.
    Native,
    /// The operation executes natively while retaining one virtual allocation.
    Virtual(VirtualAllocationKind),
    /// The operation materializes live state and returns to the oracle.
    Statepoint(PromiseStatepointKind),
}

/// One frame-specialized node in traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromiseRegionNode {
    /// The specialized IR and frame identity.
    pub key: PromiseRegionKey,
    /// The node's conservative execution classification.
    pub disposition: PromiseRegionDisposition,
}

/// The number of lexical-frame specializations retained for one IR node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromiseNodeSpecializationCount {
    /// The underlying IR node.
    pub node: IrId,
    /// The number of distinct frame signatures retained for the node.
    pub count: usize,
}

/// One oracle/materialization boundary in a region plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromiseStatepoint {
    /// The specialized node at which materialization occurs.
    pub key: PromiseRegionKey,
    /// The reason the region cannot continue through the node.
    pub kind: PromiseStatepointKind,
}

/// One virtual allocation site retained by a frame-specialized region node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromiseVirtualAllocationSite {
    /// The specialized node that owns the allocation.
    pub key: PromiseRegionKey,
    /// The virtual representation allocated at the site.
    pub kind: VirtualAllocationKind,
}

/// A read-only whole-demand Promise/PIR structural plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromiseRegionPlan {
    /// The requested region entry and its initial frame signature.
    pub entry: PromiseRegionKey,
    /// Frame-specialized nodes admitted to the region, in deterministic traversal order.
    pub nodes: Vec<PromiseRegionNode>,
    /// The number of distinct underlying IR nodes represented by `nodes`.
    pub unique_ir_nodes: usize,
    /// The total number of frame-specialized nodes.
    pub specialization_count: usize,
    /// Nonzero per-node specialization counts in ascending IR-id order.
    pub specializations_by_node: Vec<PromiseNodeSpecializationCount>,
    /// The largest specialization count observed for any one IR node.
    pub max_specializations_per_node: usize,
    /// Virtual allocation sites classified by representation kind.
    pub virtual_allocations: VirtualAllocationCounts,
    /// Individually iterable virtual allocation sites.
    pub virtual_allocation_sites: Vec<PromiseVirtualAllocationSite>,
    /// Oracle/materialization boundaries encountered by the planner.
    pub statepoints: Vec<PromiseStatepoint>,
    /// Whether the entry itself is the plan's only node and is a statepoint.
    pub entry_is_only_statepoint: bool,
}

/// Fail-closed errors from Promise/PIR structural planning.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PromiseRegionError {
    /// The configured specialization cap was zero.
    #[error("Promise/PIR specialization cap must be nonzero")]
    InvalidSpecializationCap,
    /// The dense fact table does not match the IR arena.
    #[error("IR fact count {facts} does not match node count {nodes}")]
    InvalidFactCount {
        /// The number of fact records.
        facts: usize,
        /// The number of arena nodes.
        nodes: usize,
    },
    /// A node id did not exist in the arena.
    #[error("invalid IR node id {id:?}")]
    InvalidNode {
        /// The invalid node id.
        id: IrId,
    },
    /// A reachable node graph contained a cycle.
    #[error("cyclic IR graph at node {id:?}")]
    Cycle {
        /// A node on the detected cycle.
        id: IrId,
    },
    /// A node payload did not match its node kind.
    #[error("invalid payload for {kind:?} node {id:?}: expected {expected}")]
    InvalidPayload {
        /// The malformed node.
        id: IrId,
        /// The node's declared kind.
        kind: IrKind,
        /// The required payload shape.
        expected: &'static str,
    },
    /// A child-pool slice was outside its side table.
    #[error("invalid child slice {slice:?} at node {id:?}")]
    InvalidChildSlice {
        /// The referencing node.
        id: IrId,
        /// The invalid slice.
        slice: IrChildSlice,
    },
    /// A binding slice was outside its side table.
    #[error("invalid binding slice {slice:?} at node {id:?}")]
    InvalidBindingSlice {
        /// The referencing node.
        id: IrId,
        /// The invalid slice.
        slice: IrBindingSlice,
    },
    /// An attribute path id did not exist.
    #[error("invalid attribute path {path:?} at node {id:?}")]
    InvalidAttrPath {
        /// The referencing node.
        id: IrId,
        /// The invalid path id.
        path: IrAttrPathId,
    },
    /// A static shape id did not exist.
    #[error("invalid shape {shape:?} at node {id:?}")]
    InvalidShape {
        /// The referencing node.
        id: IrId,
        /// The invalid shape id.
        shape: IrShapeId,
    },
    /// An attrset's shape and binding metadata disagreed.
    #[error("attrset shape {shape:?} disagrees with bindings at node {id:?}")]
    InvalidAttrSetShape {
        /// The malformed attrset.
        id: IrId,
        /// The inconsistent shape id.
        shape: IrShapeId,
    },
    /// A symbol did not exist in the symbol table.
    #[error("invalid symbol {symbol:?} at node {id:?}")]
    InvalidSymbol {
        /// The referencing node.
        id: IrId,
        /// The invalid symbol.
        symbol: Symbol,
    },
    /// A frame id did not exist.
    #[error("invalid frame {frame:?} at node {id:?}")]
    InvalidFrame {
        /// The referencing node.
        id: IrId,
        /// The invalid frame.
        frame: FrameId,
    },
    /// A `with` chain id did not exist.
    #[error("invalid with-chain {chain} at node {id:?}")]
    InvalidWithChain {
        /// The referencing node.
        id: IrId,
        /// The invalid chain id.
        chain: u32,
    },
    /// An attrset's recursion flag and frame metadata disagreed.
    #[error("invalid recursive attrset frame metadata at node {id:?}")]
    InvalidAttrSetFrame {
        /// The malformed attrset.
        id: IrId,
    },
    /// One IR node exceeded the configured frame-specialization cap.
    #[error("node {id:?} requires more than {cap} Promise/PIR frame specializations")]
    SpecializationCap {
        /// The over-specialized node.
        id: IrId,
        /// The configured per-node cap.
        cap: usize,
    },
}

/// Plans a conservative whole-demand Promise/PIR region.
///
/// The function validates all IR reachable from `entry`, including descendants
/// below statepoints, before producing a report. Planning is non-mutating:
/// neither the arena nor its analysis facts are changed.
///
/// # Errors
///
/// Returns [`PromiseRegionError`] for malformed reachable IR, inconsistent side
/// tables, cycles, an invalid initial frame, a zero specialization cap, or a
/// node that exceeds the configured per-node frame-specialization cap.
pub fn plan_promise_region(
    ir: &Ir,
    entry: IrId,
    initial_frame: Option<FrameId>,
    options: PromiseRegionOptions,
) -> Result<PromiseRegionPlan, PromiseRegionError> {
    PromiseRegionPlanner::new(ir, options).run(entry, initial_frame)
}

struct PromiseRegionPlanner<'a> {
    ir: &'a Ir,
    options: PromiseRegionOptions,
}

impl<'a> PromiseRegionPlanner<'a> {
    fn new(ir: &'a Ir, options: PromiseRegionOptions) -> Self {
        Self { ir, options }
    }

    fn run(
        &self,
        entry: IrId,
        initial_frame: Option<FrameId>,
    ) -> Result<PromiseRegionPlan, PromiseRegionError> {
        if self.options.specialization_cap == 0 {
            return Err(PromiseRegionError::InvalidSpecializationCap);
        }
        let node_count = self.ir.arena.nodes().len();
        if self.ir.facts.len() != node_count {
            return Err(PromiseRegionError::InvalidFactCount {
                facts: self.ir.facts.len(),
                nodes: node_count,
            });
        }
        self.node(entry)?;
        if let Some(frame) = initial_frame {
            self.check_frame(entry, frame)?;
        }
        let mut colors = vec![0_u8; node_count];
        self.validate_graph(entry, &mut colors)?;

        let entry_key = PromiseRegionKey {
            node: entry,
            frame: initial_frame,
        };
        let mut queue = VecDeque::from([entry_key]);
        let mut seen = HashSet::new();
        let mut represented_nodes = HashSet::new();
        let mut counts = vec![0_usize; node_count];
        let mut nodes = Vec::new();
        let mut statepoints = Vec::new();
        let mut virtual_allocations = VirtualAllocationCounts::default();
        let mut virtual_allocation_sites = Vec::new();

        while let Some(key) = queue.pop_front() {
            if !seen.insert(key) {
                continue;
            }
            let count = counts
                .get_mut(key.node.index())
                .ok_or(PromiseRegionError::InvalidNode { id: key.node })?;
            *count += 1;
            if *count > self.options.specialization_cap {
                return Err(PromiseRegionError::SpecializationCap {
                    id: key.node,
                    cap: self.options.specialization_cap,
                });
            }
            represented_nodes.insert(key.node);

            let node = *self.node(key.node)?;
            let disposition = self.classify(key.node, node)?;
            if let PromiseRegionDisposition::Virtual(kind) = disposition {
                virtual_allocations.record(kind);
                virtual_allocation_sites.push(PromiseVirtualAllocationSite { key, kind });
            }
            if !matches!(disposition, PromiseRegionDisposition::Statepoint(_))
                && self.apply_allocates_virtual_frame(node)?
            {
                virtual_allocations.record(VirtualAllocationKind::Frame);
                virtual_allocation_sites.push(PromiseVirtualAllocationSite {
                    key,
                    kind: VirtualAllocationKind::Frame,
                });
            }
            if let PromiseRegionDisposition::Statepoint(kind) = disposition {
                statepoints.push(PromiseStatepoint { key, kind });
            } else {
                queue.extend(self.planning_children(key, node)?);
            }
            nodes.push(PromiseRegionNode { key, disposition });
        }

        let max_specializations_per_node = counts.iter().copied().max().unwrap_or(0);
        let specializations_by_node = counts
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, count)| {
                (count != 0).then(|| PromiseNodeSpecializationCount {
                    node: IrId::new(index as u32),
                    count,
                })
            })
            .collect();
        let entry_is_only_statepoint = nodes.len() == 1
            && matches!(
                nodes.first().map(|node| node.disposition),
                Some(PromiseRegionDisposition::Statepoint(_))
            );
        Ok(PromiseRegionPlan {
            entry: entry_key,
            unique_ir_nodes: represented_nodes.len(),
            specialization_count: nodes.len(),
            specializations_by_node,
            max_specializations_per_node,
            virtual_allocations,
            virtual_allocation_sites,
            statepoints,
            entry_is_only_statepoint,
            nodes,
        })
    }

    fn classify(
        &self,
        id: IrId,
        node: IrNode,
    ) -> Result<PromiseRegionDisposition, PromiseRegionError> {
        if !node.effect.is_speculable() {
            return Ok(PromiseRegionDisposition::Statepoint(
                PromiseStatepointKind::Effect,
            ));
        }
        let disposition = match (node.kind, node.data) {
            (IrKind::GlobalVar, _) => {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::Global)
            }
            (IrKind::With, _) | (_, IrData::DialectScopeVar { .. }) => {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::DynamicScope)
            }
            (_, IrData::DialectNode { .. }) => {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::Dialect)
            }
            (
                IrKind::AttrSet,
                IrData::AttrSet {
                    recursive: true, ..
                },
            ) => PromiseRegionDisposition::Statepoint(PromiseStatepointKind::RecursiveAttrSet),
            (
                IrKind::AttrSet,
                IrData::AttrSet {
                    has_dynamic: true, ..
                },
            ) => PromiseRegionDisposition::Statepoint(PromiseStatepointKind::DynamicAttrSet),
            (IrKind::AttrSet, _) => PromiseRegionDisposition::Virtual(VirtualAllocationKind::Attrs),
            (IrKind::List, _) => PromiseRegionDisposition::Virtual(VirtualAllocationKind::List),
            (IrKind::ThunkAlloc, _) => {
                PromiseRegionDisposition::Virtual(VirtualAllocationKind::Promise)
            }
            (IrKind::Lambda, IrData::Lambda { pattern, .. })
                if self.node(pattern)?.kind == IrKind::FormalSet =>
            {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::FormalSetLambda)
            }
            (IrKind::Lambda, _) => {
                PromiseRegionDisposition::Virtual(VirtualAllocationKind::Closure)
            }
            (IrKind::Formal, IrData::Formal { default: None, .. }) => {
                PromiseRegionDisposition::Native
            }
            (IrKind::Let, IrData::Let { bindings, .. })
                if self.bindings_have_dynamic(id, bindings)? =>
            {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::Unsupported)
            }
            (IrKind::Let, IrData::Let { frame: Some(_), .. }) => {
                PromiseRegionDisposition::Virtual(VirtualAllocationKind::Frame)
            }
            (
                IrKind::Select,
                IrData::Select {
                    default: Some(_), ..
                },
            ) => PromiseRegionDisposition::Statepoint(PromiseStatepointKind::DefaultSelect),
            (IrKind::Select, IrData::Select { path, .. })
            | (IrKind::HasAttr, IrData::HasAttr { path, .. })
                if self.path_is_dynamic(id, path)? =>
            {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::DynamicSelect)
            }
            (IrKind::Apply, IrData::Pair { first, .. })
                if !self.is_statically_known_lambda(first)? =>
            {
                PromiseRegionDisposition::Statepoint(PromiseStatepointKind::UnknownCall)
            }
            (
                IrKind::Int
                | IrKind::Float
                | IrKind::Bool
                | IrKind::Null
                | IrKind::Str
                | IrKind::Path
                | IrKind::Uri
                | IrKind::SearchPath
                | IrKind::LocalVar
                | IrKind::UpvalVar
                | IrKind::BuiltinAttr
                | IrKind::Apply
                | IrKind::Select
                | IrKind::HasAttr
                | IrKind::Let
                | IrKind::If
                | IrKind::BinOp
                | IrKind::UnaryOp
                | IrKind::Interp
                | IrKind::PrimOp,
                _,
            ) => PromiseRegionDisposition::Native,
            _ => PromiseRegionDisposition::Statepoint(PromiseStatepointKind::Unsupported),
        };
        Ok(disposition)
    }

    fn is_statically_known_lambda(&self, id: IrId) -> Result<bool, PromiseRegionError> {
        Ok(self.statically_known_lambda(id)?.is_some())
    }

    fn apply_allocates_virtual_frame(&self, node: IrNode) -> Result<bool, PromiseRegionError> {
        let (IrKind::Apply, IrData::Pair { first, .. }) = (node.kind, node.data) else {
            return Ok(false);
        };
        let Some((_, lambda)) = self.statically_known_lambda(first)? else {
            return Ok(false);
        };
        let IrData::Lambda { pattern, .. } = lambda.data else {
            return Ok(false);
        };
        Ok(self.node(pattern)?.kind == IrKind::Formal)
    }

    fn statically_known_lambda(
        &self,
        mut id: IrId,
    ) -> Result<Option<(IrId, IrNode)>, PromiseRegionError> {
        let mut peeled = 0_usize;
        loop {
            let node = *self.node(id)?;
            match (node.kind, node.data) {
                (IrKind::Lambda, _) => return Ok(Some((id, node))),
                (IrKind::ThunkAlloc, IrData::Node(body)) if peeled == 0 => {
                    id = body;
                    peeled += 1;
                }
                _ => return Ok(None),
            }
        }
    }

    fn planning_children(
        &self,
        key: PromiseRegionKey,
        node: IrNode,
    ) -> Result<Vec<PromiseRegionKey>, PromiseRegionError> {
        match (node.kind, node.data) {
            // Evaluating either form allocates deferred work; its body runs only
            // at a later force or application entry. A whole-demand compiler
            // may reconnect that body after value-flow analysis proves the
            // demand edge, but a structural walk must not claim it eagerly.
            (IrKind::Lambda | IrKind::ThunkAlloc, _) => Ok(Vec::new()),
            (IrKind::Apply, IrData::Pair { first, second }) => {
                let mut children = vec![
                    PromiseRegionKey {
                        node: first,
                        frame: key.frame,
                    },
                    PromiseRegionKey {
                        node: second,
                        frame: key.frame,
                    },
                ];
                let Some((lambda_id, lambda)) = self.statically_known_lambda(first)? else {
                    return Ok(children);
                };
                if lambda_id != first {
                    children.push(PromiseRegionKey {
                        node: lambda_id,
                        frame: key.frame,
                    });
                }
                let IrData::Lambda {
                    pattern,
                    body,
                    frame,
                } = lambda.data
                else {
                    return Ok(children);
                };
                // Formal-set binding is a statepoint on the lambda node. Do not
                // bypass it by admitting its body syntactically.
                if self.node(pattern)?.kind == IrKind::Formal {
                    children.push(PromiseRegionKey {
                        node: pattern,
                        frame: key.frame,
                    });
                    children.push(PromiseRegionKey {
                        node: body,
                        frame: frame.or(key.frame),
                    });
                }
                Ok(children)
            }
            (
                IrKind::Let,
                IrData::Let {
                    bindings,
                    body,
                    frame,
                },
            ) => {
                let nested_frame = frame.or(key.frame);
                let mut children = Vec::new();
                self.binding_children(key.node, bindings, &mut children)?;
                children.push(body);
                Ok(children
                    .into_iter()
                    .map(|child| PromiseRegionKey {
                        node: child,
                        frame: nested_frame,
                    })
                    .collect())
            }
            (_, _) => Ok(self
                .node_children(key.node, node)?
                .into_iter()
                .map(|child| PromiseRegionKey {
                    node: child,
                    frame: key.frame,
                })
                .collect()),
        }
    }

    fn validate_graph(&self, id: IrId, colors: &mut [u8]) -> Result<(), PromiseRegionError> {
        let color = colors
            .get(id.index())
            .copied()
            .ok_or(PromiseRegionError::InvalidNode { id })?;
        if color == 1 {
            return Err(PromiseRegionError::Cycle { id });
        }
        if color == 2 {
            return Ok(());
        }
        colors[id.index()] = 1;
        let node = *self.node(id)?;
        self.validate_node(id, node)?;
        for child in self.node_children(id, node)? {
            self.validate_graph(child, colors)?;
        }
        colors[id.index()] = 2;
        Ok(())
    }

    fn validate_node(&self, id: IrId, node: IrNode) -> Result<(), PromiseRegionError> {
        if !payload_matches(node.kind, node.data) {
            return Err(PromiseRegionError::InvalidPayload {
                id,
                kind: node.kind,
                expected: expected_payload(node.kind),
            });
        }
        match node.data {
            IrData::Symbol(symbol) | IrData::GlobalVar { symbol, .. } => {
                self.check_symbol(id, symbol)?;
            }
            IrData::SearchPath { literal, .. } => self.check_symbol(id, literal)?,
            IrData::PrimOp { symbol, .. } => self.check_symbol(id, symbol)?,
            IrData::DialectScopeVar { symbol, chain, .. } => {
                self.check_symbol(id, symbol)?;
                self.with_chain(id, chain)?;
            }
            IrData::Lambda { pattern, frame, .. } => {
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                }
                if !matches!(self.node(pattern)?.kind, IrKind::Formal | IrKind::FormalSet) {
                    return Err(PromiseRegionError::InvalidPayload {
                        id,
                        kind: node.kind,
                        expected: "lambda payload with formal pattern",
                    });
                }
            }
            IrData::Let { frame, .. } => {
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                }
            }
            IrData::AttrSet {
                shape,
                bindings,
                recursive,
                has_dynamic,
                frame,
            } => {
                if recursive != frame.is_some() {
                    return Err(PromiseRegionError::InvalidAttrSetFrame { id });
                }
                if let Some(frame) = frame {
                    self.check_frame(id, frame)?;
                }
                self.validate_attrset_shape(id, shape, bindings, has_dynamic)?;
            }
            IrData::FormalSet { formals, alias, .. } => {
                if let Some(alias) = alias {
                    self.check_symbol(id, alias)?;
                }
                for formal in self.child_slice(id, formals)? {
                    if self.node(*formal)?.kind != IrKind::Formal {
                        return Err(PromiseRegionError::InvalidPayload {
                            id,
                            kind: node.kind,
                            expected: "formal-set payload containing only formal nodes",
                        });
                    }
                }
            }
            IrData::Formal { name, .. } => self.check_symbol(id, name)?,
            _ => {}
        }
        Ok(())
    }

    fn node_children(&self, id: IrId, node: IrNode) -> Result<Vec<IrId>, PromiseRegionError> {
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
            IrData::Pair { first, second } => children.extend([first, second]),
            IrData::Triple {
                first,
                second,
                third,
            } => children.extend([first, second, third]),
            IrData::Children(slice) => {
                children.extend_from_slice(self.child_slice(id, slice)?);
            }
            IrData::Bindings(slice) => self.binding_children(id, slice, &mut children)?,
            IrData::Binary { lhs, rhs, .. } => children.extend([lhs, rhs]),
            IrData::Unary { operand, .. } => children.push(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                children.push(receiver);
                children.extend(default);
                self.path_children(id, path, &mut children)?;
            }
            IrData::HasAttr { receiver, path, .. } => {
                children.push(receiver);
                self.path_children(id, path, &mut children)?;
            }
            IrData::PrimOp { args, .. } => {
                children.extend_from_slice(self.child_slice(id, args)?);
            }
            IrData::DialectNode { argument, .. } => children.push(argument),
            IrData::DialectScopeVar { chain, .. } => {
                children.extend_from_slice(&self.with_chain(id, chain)?.scopes);
            }
            IrData::Lambda { pattern, body, .. } => children.extend([pattern, body]),
            IrData::Let { bindings, body, .. } => {
                self.binding_children(id, bindings, &mut children)?;
                children.push(body);
            }
            IrData::AttrSet { bindings, .. } => {
                self.binding_children(id, bindings, &mut children)?;
            }
            IrData::FormalSet { formals, .. } => {
                children.extend_from_slice(self.child_slice(id, formals)?);
            }
            IrData::Formal { default, .. } => children.extend(default),
        }
        for child in &children {
            self.node(*child)?;
        }
        Ok(children)
    }

    fn binding_children(
        &self,
        id: IrId,
        slice: IrBindingSlice,
        children: &mut Vec<IrId>,
    ) -> Result<(), PromiseRegionError> {
        for binding in self.bindings(id, slice)? {
            children.push(binding.value);
            if let IrAttrPathSegment::Dynamic(dynamic) = binding.key {
                children.push(dynamic);
            } else if let IrAttrPathSegment::Static(symbol) = binding.key {
                self.check_symbol(id, symbol)?;
            }
        }
        Ok(())
    }

    fn path_children(
        &self,
        id: IrId,
        path: IrAttrPathId,
        children: &mut Vec<IrId>,
    ) -> Result<(), PromiseRegionError> {
        for segment in self.attr_path(id, path)? {
            match *segment {
                IrAttrPathSegment::Static(symbol) => self.check_symbol(id, symbol)?,
                IrAttrPathSegment::Dynamic(dynamic) => children.push(dynamic),
            }
        }
        Ok(())
    }

    fn path_is_dynamic(&self, id: IrId, path: IrAttrPathId) -> Result<bool, PromiseRegionError> {
        Ok(self
            .attr_path(id, path)?
            .iter()
            .any(|segment| matches!(segment, IrAttrPathSegment::Dynamic(_))))
    }

    fn bindings_have_dynamic(
        &self,
        id: IrId,
        bindings: IrBindingSlice,
    ) -> Result<bool, PromiseRegionError> {
        Ok(self
            .bindings(id, bindings)?
            .iter()
            .any(|binding| matches!(binding.key, IrAttrPathSegment::Dynamic(_))))
    }

    fn validate_attrset_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
        bindings: IrBindingSlice,
        has_dynamic: bool,
    ) -> Result<(), PromiseRegionError> {
        let shape_table = self
            .ir
            .shapes
            .get(shape.index())
            .ok_or(PromiseRegionError::InvalidShape { id, shape })?;
        let mut keys = Vec::new();
        let mut dynamic = false;
        for binding in self.bindings(id, bindings)? {
            match binding.key {
                IrAttrPathSegment::Static(symbol) => {
                    self.check_symbol(id, symbol)?;
                    keys.push(symbol);
                }
                IrAttrPathSegment::Dynamic(_) => dynamic = true,
            }
        }
        if shape_table.keys.as_ref() == keys.as_slice() && dynamic == has_dynamic {
            Ok(())
        } else {
            Err(PromiseRegionError::InvalidAttrSetShape { id, shape })
        }
    }

    fn node(&self, id: IrId) -> Result<&IrNode, PromiseRegionError> {
        self.ir
            .arena
            .node(id)
            .ok_or(PromiseRegionError::InvalidNode { id })
    }

    fn child_slice(&self, id: IrId, slice: IrChildSlice) -> Result<&[IrId], PromiseRegionError> {
        self.ir
            .arena
            .child_slice(slice)
            .ok_or(PromiseRegionError::InvalidChildSlice { id, slice })
    }

    fn bindings(
        &self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<&[crate::ir::IrBinding], PromiseRegionError> {
        let start = slice.start as usize;
        let end = start
            .checked_add(slice.len())
            .ok_or(PromiseRegionError::InvalidBindingSlice { id, slice })?;
        self.ir
            .bindings
            .get(start..end)
            .ok_or(PromiseRegionError::InvalidBindingSlice { id, slice })
    }

    fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
    ) -> Result<&[IrAttrPathSegment], PromiseRegionError> {
        self.ir
            .attr_paths
            .get(path.index())
            .map(AsRef::as_ref)
            .ok_or(PromiseRegionError::InvalidAttrPath { id, path })
    }

    fn check_symbol(&self, id: IrId, symbol: Symbol) -> Result<(), PromiseRegionError> {
        if self.options.symbol_validation == PromiseRegionSymbolValidation::ExternallyRemapped
            || self.ir.symbols.resolve(symbol).is_some()
        {
            Ok(())
        } else {
            Err(PromiseRegionError::InvalidSymbol { id, symbol })
        }
    }

    fn check_frame(&self, id: IrId, frame: FrameId) -> Result<(), PromiseRegionError> {
        if self.ir.frames.get(frame.index()).is_some() {
            Ok(())
        } else {
            Err(PromiseRegionError::InvalidFrame { id, frame })
        }
    }

    fn with_chain(
        &self,
        id: IrId,
        chain: u32,
    ) -> Result<&crate::ir::IrWithChain, PromiseRegionError> {
        self.ir
            .with_chains
            .get(chain as usize)
            .ok_or(PromiseRegionError::InvalidWithChain { id, chain })
    }
}

fn payload_matches(kind: IrKind, data: IrData) -> bool {
    match kind {
        IrKind::Int => matches!(data, IrData::Int(_)),
        IrKind::Float => matches!(data, IrData::Float(_)),
        IrKind::Bool => matches!(data, IrData::Bool(_)),
        IrKind::Null => matches!(data, IrData::None),
        IrKind::Str | IrKind::Path | IrKind::Uri | IrKind::BuiltinAttr => {
            matches!(data, IrData::Symbol(_))
        }
        IrKind::LocalVar => matches!(data, IrData::Local { .. }),
        IrKind::UpvalVar => matches!(data, IrData::Upval { .. }),
        IrKind::GlobalVar => matches!(data, IrData::GlobalVar { .. }),
        IrKind::SearchPath => matches!(data, IrData::SearchPath { .. }),
        IrKind::List => matches!(data, IrData::Children(_)),
        IrKind::AttrSet => matches!(data, IrData::AttrSet { .. }),
        IrKind::Lambda => matches!(data, IrData::Lambda { .. }),
        IrKind::FormalSet => matches!(data, IrData::FormalSet { .. }),
        IrKind::Formal => matches!(data, IrData::Formal { .. }),
        IrKind::Apply | IrKind::With | IrKind::Assert => matches!(data, IrData::Pair { .. }),
        IrKind::Select => matches!(data, IrData::Select { .. }),
        IrKind::HasAttr => matches!(data, IrData::HasAttr { .. }),
        IrKind::Let => matches!(data, IrData::Let { .. }),
        IrKind::If => matches!(data, IrData::Triple { .. }),
        IrKind::BinOp => matches!(data, IrData::Binary { .. }),
        IrKind::UnaryOp => matches!(data, IrData::Unary { .. }),
        IrKind::Interp => matches!(data, IrData::Node(_) | IrData::Children(_) | IrData::None),
        IrKind::ThunkAlloc => matches!(data, IrData::Node(_)),
        IrKind::PrimOp => matches!(
            data,
            IrData::PrimOp { .. } | IrData::DialectNode { .. } | IrData::DialectScopeVar { .. }
        ),
    }
}

const fn expected_payload(kind: IrKind) -> &'static str {
    match kind {
        IrKind::Int => "integer payload",
        IrKind::Float => "float payload",
        IrKind::Bool => "boolean payload",
        IrKind::Null => "empty payload",
        IrKind::Str | IrKind::Path | IrKind::Uri | IrKind::BuiltinAttr => "symbol payload",
        IrKind::LocalVar => "local slot payload",
        IrKind::UpvalVar => "upvalue slot payload",
        IrKind::GlobalVar => "global-var payload",
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
        IrKind::ThunkAlloc => "thunk body payload",
        IrKind::PrimOp => "primop payload",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{EffectClass, IrArena, IrFacts, IrNode};
    use crate::scope::FrameInfo;
    use crate::syntax::{Span, SymbolTable, parse_str};
    use crate::{lower, resolve};

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    fn plan(source: &str) -> PromiseRegionPlan {
        let ir = lowered(source);
        plan_promise_region(&ir, ir.root, None, PromiseRegionOptions::default())
            .expect("region plans")
    }

    #[test]
    fn plans_static_attrset_and_defers_lazy_value_bodies() {
        let report = plan("{ answer = 40 + 2; values = [ 1 2 ]; }");

        assert_eq!(report.statepoints, []);
        assert_eq!(report.virtual_allocations.attrs, 1);
        assert!(report.virtual_allocations.promises >= 1);
        assert_eq!(report.virtual_allocations.lists, 0);
        assert_eq!(
            report.virtual_allocation_sites.len(),
            report.virtual_allocations.total()
        );
        assert!(!report.entry_is_only_statepoint);
    }

    #[test]
    fn dynamic_attrset_is_a_materialization_boundary() {
        let report = plan("let key = \"answer\"; in { ${key} = 42; }");

        assert!(
            report
                .statepoints
                .iter()
                .any(|statepoint| { statepoint.kind == PromiseStatepointKind::DynamicAttrSet })
        );
    }

    #[test]
    fn plans_direct_simple_lambda_application_without_a_call_statepoint() {
        let report = plan("(x: x) 1");

        assert_eq!(report.statepoints, []);
        assert_eq!(report.virtual_allocations.closures, 1);
    }

    #[test]
    fn deferred_lambda_body_is_entered_only_through_application() {
        let allocation = plan("x: let y = 1; in y");
        assert_eq!(allocation.unique_ir_nodes, 1);
        assert_eq!(allocation.virtual_allocations.closures, 1);
        assert_eq!(allocation.virtual_allocations.frames, 0);

        let application = plan("(x: let y = 1; in y) 1");
        assert!(application.unique_ir_nodes > allocation.unique_ir_nodes);
        assert_eq!(application.virtual_allocations.closures, 1);
        assert_eq!(application.virtual_allocations.frames, 2);
    }

    #[test]
    fn effectful_node_is_a_materialization_boundary() {
        let span = Span::new(0, 1);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                span,
                EffectClass::new(1, false),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let ir = raw_ir(IrId::new(0), arena, Box::new([]), Box::new([]));

        let report = plan_promise_region(&ir, ir.root, None, PromiseRegionOptions::default())
            .expect("effect boundary plans");
        assert_eq!(report.statepoints[0].kind, PromiseStatepointKind::Effect);
        assert!(report.entry_is_only_statepoint);
    }

    #[test]
    fn rejects_malformed_side_table() {
        let span = Span::new(0, 1);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::List,
                span,
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(3, 1)),
            )],
            Vec::new(),
        );
        let ir = raw_ir(IrId::new(0), arena, Box::new([]), Box::new([]));

        assert!(matches!(
            plan_promise_region(&ir, ir.root, None, PromiseRegionOptions::default()),
            Err(PromiseRegionError::InvalidChildSlice { .. })
        ));
    }

    #[test]
    fn externally_remapped_symbols_keep_other_validation_enabled() {
        let root = IrId::new(0);
        let span = Span::new(0, 1);
        let symbol = Symbol::new(99);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                span,
                EffectClass::pure(),
                IrData::Symbol(symbol),
            )],
            Vec::new(),
        );
        let ir = raw_ir(root, arena, Box::new([]), Box::new([]));

        assert_eq!(
            plan_promise_region(&ir, root, None, PromiseRegionOptions::default()),
            Err(PromiseRegionError::InvalidSymbol { id: root, symbol })
        );
        let plan = plan_promise_region(
            &ir,
            root,
            None,
            PromiseRegionOptions {
                symbol_validation: PromiseRegionSymbolValidation::ExternallyRemapped,
                ..PromiseRegionOptions::default()
            },
        )
        .expect("externally remapped symbol plans");
        assert!(plan.statepoints.is_empty());
        assert_eq!(plan.unique_ir_nodes, 1);
    }

    #[test]
    fn rejects_reachable_ir_cycles() {
        let root = IrId::new(0);
        let span = Span::new(0, 1);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                span,
                EffectClass::pure(),
                IrData::Node(root),
            )],
            Vec::new(),
        );
        let ir = raw_ir(root, arena, Box::new([]), Box::new([]));

        assert_eq!(
            plan_promise_region(&ir, root, None, PromiseRegionOptions::default()),
            Err(PromiseRegionError::Cycle { id: root })
        );
    }

    #[test]
    fn specializes_shared_node_by_frame_and_enforces_cap() {
        let span = Span::new(0, 1);
        let shared = IrId::new(0);
        let first_let = IrId::new(1);
        let second_let = IrId::new(2);
        let root = IrId::new(3);
        let nodes = vec![
            IrNode::new(IrKind::Int, span, EffectClass::pure(), IrData::Int(1)),
            IrNode::new(
                IrKind::Let,
                span,
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 0),
                    body: shared,
                    frame: Some(FrameId::new(0)),
                },
            ),
            IrNode::new(
                IrKind::Let,
                span,
                EffectClass::pure(),
                IrData::Let {
                    bindings: IrBindingSlice::new(0, 0),
                    body: shared,
                    frame: Some(FrameId::new(1)),
                },
            ),
            IrNode::new(
                IrKind::List,
                span,
                EffectClass::pure(),
                IrData::Children(IrChildSlice::new(0, 2)),
            ),
        ];
        let arena = IrArena::from_raw_parts(nodes, vec![first_let, second_let]);
        let frames = vec![empty_frame(), empty_frame()].into_boxed_slice();
        let ir = raw_ir(root, arena, frames, Box::new([]));

        let report = plan_promise_region(
            &ir,
            root,
            None,
            PromiseRegionOptions {
                specialization_cap: 2,
                ..PromiseRegionOptions::default()
            },
        )
        .expect("two specializations fit");
        assert_eq!(report.specialization_count, 5);
        assert_eq!(report.unique_ir_nodes, 4);
        assert_eq!(report.max_specializations_per_node, 2);
        assert_eq!(
            report
                .specializations_by_node
                .iter()
                .find(|count| count.node == shared)
                .map(|count| count.count),
            Some(2)
        );

        assert_eq!(
            plan_promise_region(
                &ir,
                root,
                None,
                PromiseRegionOptions {
                    specialization_cap: 1,
                    ..PromiseRegionOptions::default()
                },
            ),
            Err(PromiseRegionError::SpecializationCap { id: shared, cap: 1 })
        );
    }

    fn empty_frame() -> FrameInfo {
        FrameInfo {
            slot_count: 0,
            captures: Box::new([]),
            rec: false,
            has_with: false,
        }
    }

    fn raw_ir(
        root: IrId,
        arena: IrArena,
        frames: Box<[FrameInfo]>,
        bindings: Box<[crate::ir::IrBinding]>,
    ) -> Ir {
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root,
            arena,
            facts,
            symbols: SymbolTable::new(),
            frames,
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings,
            shapes: Box::new([]),
        }
    }
}
