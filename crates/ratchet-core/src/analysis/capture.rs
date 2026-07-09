//! Free-variable capture plans for lambda and thunk allocation sites.
//!
//! Every closure the evaluator allocates — a lambda construction or a lazy
//! thunk — currently captures the whole shared lexical frame chain. The FV-5
//! flat-capture campaign wants to copy only the slots a body can actually
//! read. This pass computes that free-variable set per allocation site with a
//! slot walk over the scope-resolved IR and records a [`CapturePlan`] fact:
//!
//! - [`CapturePlan::Flat`] with the sorted `(depth, slot)` coordinate set
//!   when the body provably reads at most
//!   [`FLAT_CAPTURE_MAX_SLOTS`] coordinates of the allocation-site
//!   environment and never probes dynamic scope;
//! - [`CapturePlan::SharedChain`] otherwise, carrying the declining reason.
//!
//! Coordinates are relative to the environment active at the allocation
//! site: depth 0 names its innermost frame. The computation is a memoized
//! bottom-up fold: `free(n)` is the free-variable set of `n` relative to the
//! environment at `n`'s own evaluation point, so each arena node is computed
//! exactly once and frame-introducing nodes (lambda parameter frames, `let`
//! frames, recursive attribute-set frames — the exact set the evaluator
//! pushes) shift their children's coordinates down by one. References that
//! resolve inside body-introduced frames drop out of the shifted set, and
//! nested closures' captures flow through transitively.
//!
//! This module only produces the plan facts plus distribution data; the
//! runtime consumer is deliberately not built here.

use thiserror::Error;

use crate::ir::{
    CapturePlan, Ir, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId, IrKind,
    SharedChainReason,
};
use crate::scope::Upvalue;

/// Maximum coordinate count a flat capture plan may carry.
///
/// Chosen from the measured free-variable distribution across the repository
/// corpus (see the RFC-0007 Phase 4 Chunk D report): 8 slots cover ~97.8% of
/// allocation sites while keeping the flat capture record within one cache
/// line of inline `(depth, slot)` pairs.
pub const FLAT_CAPTURE_MAX_SLOTS: usize = 8;

/// Number of buckets in [`CaptureAnalysisReport::free_var_histogram`].
///
/// Buckets `0..FREE_VAR_HISTOGRAM_BUCKETS - 1` count sites with exactly that
/// many free variables; the last bucket aggregates everything at or above
/// `FREE_VAR_HISTOGRAM_BUCKETS - 1`.
pub const FREE_VAR_HISTOGRAM_BUCKETS: usize = 17;

/// Summary of one capture-plan annotation run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureAnalysisReport {
    /// Lambda construction sites that received a plan.
    pub lambda_sites: usize,
    /// Thunk allocation sites that received a plan.
    pub thunk_sites: usize,
    /// Sites whose plan is [`CapturePlan::Flat`].
    pub flat_plans: usize,
    /// Sites whose plan is [`CapturePlan::SharedChain`].
    pub shared_chain_plans: usize,
    /// Distribution of free-variable set sizes across all planned sites.
    ///
    /// Bucket `i < FREE_VAR_HISTOGRAM_BUCKETS - 1` counts sites with exactly
    /// `i` free variables; the final bucket aggregates larger sets. Sites
    /// declined for dynamic scope report their (still well-defined) lexical
    /// free-variable count.
    pub free_var_histogram: [usize; FREE_VAR_HISTOGRAM_BUCKETS],
    /// The largest free-variable set observed.
    pub max_free_vars: usize,
    /// Thunk allocation sites whose body is structurally silent.
    ///
    /// This is the Chunk C call-by-name measurement: a single-entry thunk
    /// whose body is a literal-shaped expression (incapable of throwing,
    /// diverging, or emitting trace output) could skip its cell entirely.
    /// The counter sizes that opportunity; no representation change is made.
    pub pure_silent_thunk_bodies: usize,
}

/// Errors returned when capture-plan analysis sees malformed IR storage.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CaptureAnalysisError {
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
    #[error("invalid attribute path at IR node {id:?}")]
    InvalidAttrPath {
        /// The node that referenced the invalid path.
        id: IrId,
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

/// Annotates every lambda and thunk allocation site with a capture plan.
///
/// The pass overwrites any existing plan facts. Nodes that are not
/// allocation sites keep `None`.
///
/// # Errors
///
/// Returns [`CaptureAnalysisError`] if the IR arena, child pool, binding
/// table, attribute-path table, or fact table are internally inconsistent.
pub fn annotate_capture_plans(
    ir: &mut Ir,
) -> Result<CaptureAnalysisReport, CaptureAnalysisError> {
    let node_count = ir.arena.nodes().len();
    if ir.facts.len() != node_count {
        return Err(CaptureAnalysisError::InvalidFactTableLength {
            expected: node_count,
            actual: ir.facts.len(),
        });
    }
    let mut report = CaptureAnalysisReport::default();
    let mut fold = FreeVarFold::new(ir);
    let mut plans: Vec<(IrId, CapturePlan)> = Vec::new();
    for index in 0..node_count {
        let id = IrId::new(index as u32);
        let node = *node(ir, id)?;
        let is_site = match (node.kind, node.data) {
            (IrKind::Lambda, IrData::Lambda { .. }) => {
                report.lambda_sites += 1;
                true
            }
            (IrKind::ThunkAlloc, IrData::Node(body)) => {
                report.thunk_sites += 1;
                if structurally_silent(ir, body)? {
                    report.pure_silent_thunk_bodies += 1;
                }
                true
            }
            _ => false,
        };
        if !is_site {
            continue;
        }
        // `free(site)` is the site's free-variable set relative to its
        // allocation environment: the lambda fold already shifts out its own
        // parameter frame, and a thunk body shares the allocation frame.
        let entry = fold.free(id)?;
        let free_count = entry.free.len();
        let bucket = free_count.min(FREE_VAR_HISTOGRAM_BUCKETS - 1);
        report.free_var_histogram[bucket] += 1;
        report.max_free_vars = report.max_free_vars.max(free_count);
        let plan = if let Some(reason) = entry.decline {
            CapturePlan::SharedChain(reason)
        } else if free_count > FLAT_CAPTURE_MAX_SLOTS {
            CapturePlan::SharedChain(SharedChainReason::TooManyFreeVars)
        } else {
            CapturePlan::Flat(entry.free.clone())
        };
        match plan {
            CapturePlan::Flat(_) => report.flat_plans += 1,
            CapturePlan::SharedChain(_) => report.shared_chain_plans += 1,
        }
        plans.push((id, plan));
    }
    for (id, plan) in plans {
        ir.facts.set_capture_plan(id, Some(plan));
    }
    Ok(report)
}

/// The memoized free-variable entry for one node.
#[derive(Clone, Debug, Default)]
struct FreeVarEntry {
    /// Sorted, deduplicated free coordinates relative to the node's own
    /// evaluation environment.
    free: Box<[Upvalue]>,
    /// A flat plan is impossible for any site containing this node.
    decline: Option<SharedChainReason>,
}

/// Memoized bottom-up free-variable computation over one IR arena.
///
/// Each node's entry is computed exactly once, so the whole-module cost is
/// linear in the arena plus the (small) merged set sizes — never the
/// per-site-times-subtree product a naive per-site walk pays.
struct FreeVarFold<'a> {
    ir: &'a Ir,
    entries: Vec<Option<FreeVarEntry>>,
}

impl<'a> FreeVarFold<'a> {
    fn new(ir: &'a Ir) -> Self {
        Self {
            entries: vec![None; ir.arena.nodes().len()],
            ir,
        }
    }

    /// Returns the memoized entry for `id`, computing it on first demand.
    fn free(&mut self, id: IrId) -> Result<&FreeVarEntry, CaptureAnalysisError> {
        if self
            .entries
            .get(id.index())
            .ok_or(CaptureAnalysisError::InvalidNode { id })?
            .is_none()
        {
            let entry = self.compute(id)?;
            self.entries[id.index()] = Some(entry);
        }
        self.entries[id.index()]
            .as_ref()
            .ok_or(CaptureAnalysisError::InvalidNode { id })
    }

    /// Merges a child's entry into an accumulator, shifting by `crossing`
    /// frames introduced between the child and the accumulating node.
    fn merge_child(
        &mut self,
        accumulator: &mut Accumulator,
        child: IrId,
        crossing: u16,
    ) -> Result<(), CaptureAnalysisError> {
        let entry = self.free(child)?;
        if let Some(reason) = entry.decline {
            accumulator.decline.get_or_insert(reason);
        }
        for capture in entry.free.iter() {
            if capture.depth >= crossing {
                accumulator.push(Upvalue {
                    depth: capture.depth - crossing,
                    slot: capture.slot,
                });
            }
        }
        Ok(())
    }

    fn compute(&mut self, id: IrId) -> Result<FreeVarEntry, CaptureAnalysisError> {
        let node = *node(self.ir, id)?;
        let mut accumulator = Accumulator::default();
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. } => {}
            IrData::DialectScopeVar { .. } => {
                // Dynamic-scope probes fall back through resolver metadata to
                // lexically captured frames the plan cannot enumerate.
                accumulator.decline = Some(SharedChainReason::DynamicScope);
            }
            IrData::Local { slot } => match u16::try_from(slot) {
                Ok(slot) => accumulator.push(Upvalue { depth: 0, slot }),
                Err(_) => {
                    accumulator.decline = Some(SharedChainReason::CoordinateOverflow);
                }
            },
            IrData::Upval { depth, slot } => {
                match (u16::try_from(depth), u16::try_from(slot)) {
                    (Ok(depth), Ok(slot)) => accumulator.push(Upvalue { depth, slot }),
                    _ => {
                        accumulator.decline = Some(SharedChainReason::CoordinateOverflow);
                    }
                }
            }
            IrData::SearchPath { search_path, .. } => {
                if let Some(search_path) = search_path {
                    self.merge_child(&mut accumulator, search_path, 0)?;
                }
            }
            IrData::Node(child) | IrData::Unary { operand: child, .. } => {
                self.merge_child(&mut accumulator, child, 0)?;
            }
            IrData::Pair { first, second }
            | IrData::Binary {
                lhs: first,
                rhs: second,
                ..
            } => {
                self.merge_child(&mut accumulator, first, 0)?;
                self.merge_child(&mut accumulator, second, 0)?;
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                self.merge_child(&mut accumulator, first, 0)?;
                self.merge_child(&mut accumulator, second, 0)?;
                self.merge_child(&mut accumulator, third, 0)?;
            }
            IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
                for child in child_ids(self.ir, id, slice)?.to_vec() {
                    self.merge_child(&mut accumulator, child, 0)?;
                }
            }
            IrData::Bindings(slice) => {
                self.merge_bindings(&mut accumulator, id, slice, 0)?;
            }
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                self.merge_child(&mut accumulator, receiver, 0)?;
                if let Some(default) = default {
                    self.merge_child(&mut accumulator, default, 0)?;
                }
                self.merge_attr_path(&mut accumulator, id, path.index())?;
            }
            IrData::HasAttr { receiver, path, .. } => {
                self.merge_child(&mut accumulator, receiver, 0)?;
                self.merge_attr_path(&mut accumulator, id, path.index())?;
            }
            IrData::DialectNode { argument, .. } => {
                self.merge_child(&mut accumulator, argument, 0)?;
            }
            IrData::Lambda { pattern, body, .. } => {
                // The lambda's parameter frame sits between its body and the
                // captured environment: shift both children out by one.
                self.merge_child(&mut accumulator, pattern, 1)?;
                self.merge_child(&mut accumulator, body, 1)?;
            }
            IrData::Let { bindings, body, .. } => {
                self.merge_bindings(&mut accumulator, id, bindings, 1)?;
                self.merge_child(&mut accumulator, body, 1)?;
            }
            IrData::AttrSet {
                bindings,
                recursive,
                ..
            } => {
                if recursive && self.rec_attrset_has_dynamic_keys(id, bindings)? {
                    // Dynamic keys of a recursive set evaluate outside the
                    // set's frame; rather than model that split schedule the
                    // plan declines.
                    accumulator.decline = Some(SharedChainReason::DynamicScope);
                } else {
                    let crossing = u16::from(recursive);
                    self.merge_bindings(&mut accumulator, id, bindings, crossing)?;
                }
            }
            IrData::FormalSet { formals, .. } => {
                for formal in child_ids(self.ir, id, formals)?.to_vec() {
                    self.merge_child(&mut accumulator, formal, 0)?;
                }
            }
            IrData::Formal { default, .. } => {
                if let Some(default) = default {
                    self.merge_child(&mut accumulator, default, 0)?;
                }
            }
        }
        Ok(accumulator.finish())
    }

    fn rec_attrset_has_dynamic_keys(
        &self,
        id: IrId,
        slice: IrBindingSlice,
    ) -> Result<bool, CaptureAnalysisError> {
        Ok(bindings(self.ir, id, slice)?
            .iter()
            .any(|binding| matches!(binding.key, IrAttrPathSegment::Dynamic(_))))
    }

    fn merge_bindings(
        &mut self,
        accumulator: &mut Accumulator,
        id: IrId,
        slice: IrBindingSlice,
        crossing: u16,
    ) -> Result<(), CaptureAnalysisError> {
        for binding in bindings(self.ir, id, slice)?.to_vec() {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                self.merge_child(accumulator, key, crossing)?;
            }
            self.merge_child(accumulator, binding.value, crossing)?;
        }
        Ok(())
    }

    fn merge_attr_path(
        &mut self,
        accumulator: &mut Accumulator,
        id: IrId,
        path: usize,
    ) -> Result<(), CaptureAnalysisError> {
        let segments = self
            .ir
            .attr_paths
            .get(path)
            .ok_or(CaptureAnalysisError::InvalidAttrPath { id })?
            .to_vec();
        for segment in segments {
            if let IrAttrPathSegment::Dynamic(dynamic) = segment {
                self.merge_child(accumulator, dynamic, 0)?;
            }
        }
        Ok(())
    }
}

/// Accumulates a node's free set before sorting and deduplication.
#[derive(Debug, Default)]
struct Accumulator {
    free: Vec<Upvalue>,
    decline: Option<SharedChainReason>,
}

impl Accumulator {
    fn push(&mut self, capture: Upvalue) {
        self.free.push(capture);
    }

    fn finish(mut self) -> FreeVarEntry {
        self.free.sort_unstable();
        self.free.dedup();
        FreeVarEntry {
            free: self.free.into_boxed_slice(),
            decline: self.decline,
        }
    }
}

/// Returns whether forcing `id` is structurally incapable of any observable
/// event, using only literal-shaped rules (no variable chasing).
///
/// This is a deliberately weaker measurement-only cousin of the strictness
/// pass's totality bits: literals, lambdas, list literals, and static-key
/// non-recursive attrset literals qualify.
fn structurally_silent(ir: &Ir, id: IrId) -> Result<bool, CaptureAnalysisError> {
    let node = *node(ir, id)?;
    Ok(match node.kind {
        IrKind::Int
        | IrKind::Float
        | IrKind::Bool
        | IrKind::Null
        | IrKind::Str
        | IrKind::Path
        | IrKind::Uri
        | IrKind::Lambda
        | IrKind::List => true,
        IrKind::AttrSet => {
            matches!(
                node.data,
                IrData::AttrSet {
                    recursive: false,
                    has_dynamic: false,
                    ..
                }
            )
        }
        _ => false,
    })
}

fn node(ir: &Ir, id: IrId) -> Result<&crate::ir::IrNode, CaptureAnalysisError> {
    ir.arena
        .node(id)
        .ok_or(CaptureAnalysisError::InvalidNode { id })
}

fn child_ids<'a>(
    ir: &'a Ir,
    id: IrId,
    slice: IrChildSlice,
) -> Result<&'a [IrId], CaptureAnalysisError> {
    ir.arena
        .child_slice(slice)
        .ok_or(CaptureAnalysisError::InvalidChildSlice { id, slice })
}

fn bindings<'a>(
    ir: &'a Ir,
    id: IrId,
    slice: IrBindingSlice,
) -> Result<&'a [crate::ir::IrBinding], CaptureAnalysisError> {
    let start = slice.start as usize;
    let end = start
        .checked_add(slice.len())
        .ok_or(CaptureAnalysisError::InvalidBindingSlice { id, slice })?;
    ir.bindings
        .get(start..end)
        .ok_or(CaptureAnalysisError::InvalidBindingSlice { id, slice })
}
